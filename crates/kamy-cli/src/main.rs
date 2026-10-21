//! `kamy` command-line entry point.
//!
//! Thin dispatcher: the clap surface lives here, every handler lives in
//! [`commands`]. Each subcommand maps to a `commands::<name>::run` call.

mod commands;
mod target;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use commands::dump::StageArg;

#[derive(Parser)]
#[command(name = "kamy", version, about = "Binary-to-binary protection engine")]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Increase log verbosity; repeat for more detail (-v, -vv, -vvv).
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Silence all logging except errors.
    #[arg(short, long, global = true)]
    quiet: bool,

    /// `EnvFilter` directives, e.g. `kamy_link=debug,warn`.
    #[arg(long, global = true)]
    log: Option<String>,

    /// Log output format.
    #[arg(long, global = true, default_value = "compact")]
    log_format: kamy_observe::LogFormat,
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
        /// Preview which functions match these name globs (repeatable).
        #[arg(long)]
        select: Vec<String>,
    },
    /// Apply transforms per a protection profile.
    Protect {
        /// Input PE to protect.
        input: PathBuf,
        /// Protection profile (YAML). Omit with --no-transform or --ssa-identity.
        #[arg(long)]
        profile: Option<PathBuf>,
        /// Protected output path.
        #[arg(short, long)]
        output: PathBuf,
        /// Write sorted old_rva,new_rva CSV using actual final RVAs.
        #[arg(long)]
        debug_map: Option<PathBuf>,
        /// Run canonical SSA identity without semantic transforms (same as --ssa-identity).
        /// Resident bodies stay in place; their references to moved code may be patched.
        #[arg(long)]
        no_transform: bool,
        /// Run canonical SSA identity without semantic transforms (same as --no-transform).
        /// Resident bodies stay in place; their references to moved code may be patched.
        #[arg(long)]
        ssa_identity: bool,
        /// SSA-lower ONLY these function RVAs (hex, comma-separated).
        #[arg(long)]
        only_rva: Option<String>,
        /// SSA-lower every function EXCEPT these RVAs (hex, comma-separated).
        #[arg(long)]
        reject_rva: Option<String>,
    },
    /// Dump a single function's IR at a chosen pipeline stage.
    Dump {
        /// Input PE.
        input: PathBuf,
        /// Entry RVA of the function to dump (hex).
        #[arg(long)]
        rva: String,
        /// Pipeline stage to run up to.
        #[arg(long, value_enum, default_value_t = StageArg::Optimize)]
        stage: StageArg,
    },
    /// Delta-debug an SSA-lowering regression down to a minimal culprit set.
    Bisect {
        /// Input PE.
        input: PathBuf,
        /// Exit code a passing run must return.
        #[arg(long)]
        expect_exit: i32,
        /// Feed this file to the target's stdin.
        #[arg(long)]
        stdin_file: Option<PathBuf>,
        /// Require the target's stdout to match this file (trailing whitespace
        /// ignored). Catches wrong-output miscompiles that still exit cleanly.
        #[arg(long)]
        expect_stdout: Option<PathBuf>,
        /// Per-run wall-clock limit in seconds.
        #[arg(long, default_value_t = 30)]
        timeout: u64,
    },
    /// Explain why functions were rejected by the SSA-identity protect.
    ExplainReject {
        /// Input PE.
        input: PathBuf,
        /// Report only this function's status (hex RVA).
        #[arg(long)]
        rva: Option<String>,
    },
    /// Test-vector equivalence check between two binaries.
    Verify {
        /// Original (unprotected) executable.
        #[arg(long)]
        original: PathBuf,
        /// Protected executable to compare against the original.
        #[arg(long)]
        protected: PathBuf,
        /// Number of random input vectors.
        #[arg(long, default_value_t = 1000)]
        vectors: u32,
    },
    /// Differential corpus tooling (build/bless/verify/list/doctor).
    Corpus {
        #[command(subcommand)]
        cmd: CorpusCmd,
    },
    /// Build Rust SDK plugins for static module injection.
    Plugin {
        #[command(subcommand)]
        cmd: commands::plugin::Command,
    },
}

#[derive(Subcommand)]
enum CorpusCmd {
    /// Build each member's original binary.
    Build {
        #[arg(long)]
        corpus: Option<PathBuf>,
    },
    /// Build, observe, and record each member's golden behavior.
    Bless {
        #[arg(long)]
        corpus: Option<PathBuf>,
    },
    /// Protect each member and diff against its golden record.
    Verify {
        #[arg(long)]
        corpus: Option<PathBuf>,
        /// Verify only the named member.
        #[arg(long)]
        member: Option<String>,
        /// Keep protected artifacts on disk.
        #[arg(long)]
        keep: bool,
        /// Compare coverage against this baseline and print the delta.
        #[arg(long)]
        baseline: Option<PathBuf>,
        /// Save the resulting coverage as a baseline here.
        #[arg(long)]
        write_baseline: Option<PathBuf>,
    },
    /// List corpus members and their oracle kinds.
    List {
        #[arg(long)]
        corpus: Option<PathBuf>,
    },
    /// Oracle/ABI self-check across the corpus originals (nothing is protected).
    Doctor {
        #[arg(long)]
        corpus: Option<PathBuf>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    kamy_observe::init(&kamy_observe::LogConfig {
        verbosity: cli.verbose,
        quiet: cli.quiet,
        filter: cli.log.clone(),
        format: cli.log_format,
        ansi: None,
    })?;
    match cli.command {
        Command::Analyze {
            input,
            pdb,
            output,
            select,
        } => commands::analyze::run(&input, pdb.as_deref(), output.as_deref(), &select),
        Command::Protect {
            input,
            profile,
            output,
            debug_map,
            no_transform,
            ssa_identity,
            only_rva,
            reject_rva,
        } => commands::protect::run(commands::protect::Args {
            input,
            profile,
            output,
            debug_map,
            no_transform,
            ssa_identity,
            only_rva,
            reject_rva,
        }),
        Command::Dump { input, rva, stage } => commands::dump::run(&input, &rva, stage),
        Command::Bisect {
            input,
            expect_exit,
            stdin_file,
            expect_stdout,
            timeout,
        } => commands::bisect::run(
            &input,
            expect_exit,
            stdin_file.as_deref(),
            expect_stdout.as_deref(),
            timeout,
        ),
        Command::ExplainReject { input, rva } => {
            commands::explain_reject::run(&input, rva.as_deref())
        }
        Command::Verify {
            original,
            protected,
            vectors,
        } => commands::verify::run(&original, &protected, vectors),
        Command::Corpus { cmd } => commands::corpus::dispatch(cmd),
        Command::Plugin { cmd } => commands::plugin::dispatch(cmd),
    }
}
