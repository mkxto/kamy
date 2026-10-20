//! `kamy bisect`: delta-debug an SSA-lowering regression to a minimal culprit.

use std::path::Path;
use std::time::Duration;

use anyhow::Context as _;

pub(crate) fn run(
    input: &Path,
    expect_exit: i32,
    stdin_file: Option<&Path>,
    timeout: u64,
) -> anyhow::Result<()> {
    let stdin = match stdin_file {
        Some(p) => std::fs::read(p).with_context(|| format!("reading {}", p.display()))?,
        None => Vec::new(),
    };
    let timeout = Duration::from_secs(timeout);
    let is_pass = |protected: &Path| -> anyhow::Result<bool> {
        let out = kamy_run::run(&kamy_run::RunOptions {
            exe: protected.into(),
            stdin: stdin.clone(),
            timeout,
            ..Default::default()
        })?;
        Ok(out.exit_code == Some(expect_exit))
    };

    let outcome = kamy_triage::bisect(input, &is_pass)?;

    println!("candidates: {}", outcome.candidates);
    println!("steps:      {}", outcome.steps);
    if outcome.culprit.is_empty() {
        println!("culprit:    <none>");
    } else {
        println!("culprit:");
        for rva in &outcome.culprit {
            println!("  {rva}");
        }
    }
    if let Some(f) = outcome.fault {
        println!(
            "fault: code={:#x} address={:#x} rva={:#x}",
            f.code, f.address, f.rva
        );
    }

    if let Some(culprit) = outcome.culprit.first() {
        eprintln!(
            "→ deep-dive the culprit in x64dbg; inspect: kamy dump {} --rva {:#x} --stage regalloc",
            input.display(),
            culprit.get()
        );
    }
    Ok(())
}
