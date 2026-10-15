//! `kamy` command-line entry point.
//!
//! Thin consumer of the engine library crates (grilling D15). Argument parsing
//! and profile loading are wired here; the protection pipeline itself lands in
//! Phase 2 and is reported as pending until then.

use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use kamy_config::Config;

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
        /// Write the eligibility report here.
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
        Command::Analyze { .. } => {
            anyhow::bail!("analyze: engine pipeline not yet wired (Phase 2)");
        }
        Command::Protect { profile, .. } => {
            // Profile loading/validation is available now; the pipeline is not.
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
