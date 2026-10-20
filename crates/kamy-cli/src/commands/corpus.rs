//! `kamy corpus`: build/bless/verify/list/doctor over the differential corpus.

use std::path::Path;

use crate::CorpusCmd;

use super::{corpus_dir, print_coverage, report_to_coverage};

pub(crate) fn dispatch(cmd: CorpusCmd) -> anyhow::Result<()> {
    match cmd {
        CorpusCmd::Build { corpus } => kamy_corpus::build_corpus(&corpus_dir(corpus)?),
        CorpusCmd::Bless { corpus } => kamy_corpus::bless_corpus(&corpus_dir(corpus)?),
        CorpusCmd::List { corpus } => kamy_corpus::list_corpus(&corpus_dir(corpus)?),
        CorpusCmd::Verify {
            corpus,
            member,
            keep,
            baseline,
            write_baseline,
        } => verify(
            &corpus_dir(corpus)?,
            member,
            keep,
            baseline.as_deref(),
            write_baseline.as_deref(),
        ),
        CorpusCmd::Doctor { corpus } => doctor(&corpus_dir(corpus)?),
    }
}

/// Run differential verification, print the coverage table, optionally save and
/// diff a baseline, then error if any member diverged.
fn verify(
    dir: &Path,
    member: Option<String>,
    keep: bool,
    baseline: Option<&Path>,
    write_baseline: Option<&Path>,
) -> anyhow::Result<()> {
    let opts = kamy_corpus::VerifyOptions { member, keep };
    let cov = kamy_corpus::verify_corpus(
        dir,
        &|inp, outp| {
            let report = kamy_triage::protect_identity(inp, outp, None)?;
            Ok(report_to_coverage(&report))
        },
        &opts,
    )?;
    print_coverage(&cov);

    if let Some(path) = write_baseline {
        cov.save(path)?;
    }
    if let Some(path) = baseline {
        let old = kamy_corpus::CorpusCoverage::load(path)?;
        println!("baseline delta:");
        for line in kamy_corpus::coverage_delta(&old, &cov) {
            println!("  {line}");
        }
    }

    if cov.failed > 0 {
        eprintln!("→ isolate: kamy bisect <member-orig-binary> --expect-exit <code>");
        eprintln!("→ inspect IR: kamy dump <input> --rva <hex> --stage regalloc");
        anyhow::bail!("{} member(s) failed verification", cov.failed);
    }
    Ok(())
}

/// Oracle/ABI self-check across the corpus originals.
fn doctor(dir: &Path) -> anyhow::Result<()> {
    let report = kamy_corpus::doctor_corpus(dir)?;
    let mut failed = 0usize;
    for (name, ok, msgs) in &report.members {
        println!("{name:<24} {}", if *ok { "OK" } else { "FAIL" });
        for m in msgs {
            println!("    {m}");
        }
        if !*ok {
            failed += 1;
        }
    }
    if failed > 0 {
        anyhow::bail!("{failed} member(s) failed doctor");
    }
    Ok(())
}
