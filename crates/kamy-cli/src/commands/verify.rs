//! `kamy verify`: differential equivalence check between two binaries.

use std::path::Path;

use anyhow::Context as _;

/// Fixed seed so the differential harness is reproducible across invocations.
const VERIFY_SEED: u64 = 0xC0FF_EE15_D31B_A5E5;

pub(crate) fn run(original: &Path, protected: &Path, vectors: u32) -> anyhow::Result<()> {
    let report = kamy_verify::differential(original, protected, vectors, VERIFY_SEED)
        .context("running differential self-test")?;

    if report.passed() {
        println!("verify PASS: {} run(s), no mismatches", report.runs);
        return Ok(());
    }

    tracing::error!(
        runs = report.runs,
        mismatches = report.mismatches.len(),
        "verify failed"
    );
    for m in report.mismatches.iter().take(5) {
        tracing::warn!(
            run = m.run,
            field = %m.field,
            original = %m.original,
            protected = %m.protected,
            "mismatch"
        );
    }
    anyhow::bail!("verify failed: protected binary diverges from original");
}
