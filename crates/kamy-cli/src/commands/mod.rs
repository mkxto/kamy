//! Subcommand handlers for the `kamy` CLI. `main` is a thin dispatcher over
//! these modules; shared helpers live here.

pub(crate) mod analyze;
pub(crate) mod bisect;
pub(crate) mod corpus;
pub(crate) mod dump;
pub(crate) mod explain_reject;
pub(crate) mod protect;
pub(crate) mod verify;

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::Context as _;
use kamy_core::Rva;
use kamy_corpus::Coverage;

/// Map a linker [`Report`](kamy_link::Report) to corpus [`Coverage`]: verbatim
/// relocations (moved minus SSA-lowered) and rejections tallied by reason tag.
pub(crate) fn report_to_coverage(report: &kamy_link::Report) -> Coverage {
    let mut by_reason: BTreeMap<String, usize> = BTreeMap::new();
    for (_, reason) in &report.rejected {
        *by_reason.entry(reason.tag().to_string()).or_default() += 1;
    }
    Coverage {
        ssa_lowered: report.ssa_lowered,
        relocated: report.moved.len().saturating_sub(report.ssa_lowered),
        rejected: report.rejected.len(),
        by_reason,
    }
}

/// Resolve the corpus directory from `--corpus` or `KAMY_CORPUS_DIR`.
pub(crate) fn corpus_dir(explicit: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(dir) = explicit {
        return Ok(dir);
    }
    std::env::var_os("KAMY_CORPUS_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("corpus dir required: pass --corpus or set KAMY_CORPUS_DIR"))
}

/// Parse one RVA: optional `0x`/`0X` prefix, base 16.
pub(crate) fn parse_rva(s: &str) -> anyhow::Result<Rva> {
    let t = s.trim();
    let hex = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    let v = u32::from_str_radix(hex, 16).with_context(|| format!("parsing RVA {t:?}"))?;
    Ok(Rva::new(v))
}

/// Parse a comma-separated list of RVAs (see [`parse_rva`]).
pub(crate) fn parse_rvas(s: &str) -> anyhow::Result<Vec<Rva>> {
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(parse_rva)
        .collect()
}

/// Print the two-axis corpus report: per-member PASS/FAIL, SSA-lowered vs
/// not-covered (relocated + rejected) with a coverage percent, the corpus
/// TOTAL, and the merged rejection reasons sorted by count descending.
pub(crate) fn print_coverage(cov: &kamy_corpus::CorpusCoverage) {
    println!();
    println!(
        "coverage  {:<24} {:<7}  {:>11} {:>9} {:>8}  coverage",
        "name", "verdict", "SSA-lowered", "relocated", "rejected"
    );
    let row = |name: &str, verdict: &str, c: &Coverage| {
        let total = c.ssa_lowered + c.relocated + c.rejected;
        let pct = if total > 0 {
            100.0 * c.ssa_lowered as f64 / total as f64
        } else {
            0.0
        };
        println!(
            "          {name:<24} {verdict:<7}  {:>11} {:>9} {:>8}  {}/{total} ({pct:.1}%)",
            c.ssa_lowered, c.relocated, c.rejected, c.ssa_lowered
        );
    };
    for m in &cov.members {
        row(&m.name, if m.passed { "PASS" } else { "FAIL" }, &m.coverage);
    }
    row("TOTAL", "", &cov.total);
    println!("not covered = relocated + rejected; verbatim relocation is not SSA coverage.");
    let t = &cov.total;
    if !t.by_reason.is_empty() {
        let mut reasons: Vec<_> = t.by_reason.iter().collect();
        reasons.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
        println!("rejections by reason:");
        for (reason, count) in reasons {
            println!("          {reason:<24} {count}");
        }
    }
    println!(
        "members={} passed={} failed={}",
        cov.members.len(),
        cov.passed,
        cov.failed,
    );
}
