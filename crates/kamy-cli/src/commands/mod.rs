//! Subcommand handlers for the `kamy` CLI. `main` is a thin dispatcher over
//! these modules; shared helpers live here.

pub(crate) mod analyze;
pub(crate) mod bisect;
pub(crate) mod corpus;
pub(crate) mod dump;
pub(crate) mod explain_reject;
pub(crate) mod plugin;
pub(crate) mod protect;
pub(crate) mod verify;

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::Context as _;
use kamy_core::Rva;
use kamy_corpus::Coverage;

/// Map linker outcomes to corpus coverage, excluding import thunks and counting
/// only SSA-lowered movers as covered; any non-SSA movement remains visible.
pub(crate) fn report_to_coverage(report: &kamy_link::Report) -> Coverage {
    let mut by_reason: BTreeMap<String, usize> = BTreeMap::new();
    for (_, reason) in &report.rejected {
        *by_reason.entry(reason.tag().to_string()).or_default() += 1;
    }
    let mut actual_intensity = BTreeMap::new();
    for function in &report.functions {
        if function.lowered {
            *actual_intensity
                .entry(function.intensity.to_string())
                .or_default() += 1;
        }
    }
    Coverage {
        selected: report
            .functions
            .iter()
            .filter(|function| function.selected)
            .count(),
        eligible: report
            .functions
            .iter()
            .filter(|function| function.eligible)
            .count(),
        transformed: report
            .functions
            .iter()
            .filter(|function| function.transformed)
            .count(),
        actual_intensity,
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

/// Print execution verdicts, SSA coverage, semantic outcomes and rejection reasons.
pub(crate) fn print_coverage(cov: &kamy_corpus::CorpusCoverage) {
    println!();
    println!(
        "coverage  {:<24} {:<7}  {:>8} {:>8} {:>11} {:>11} {:>9} {:>8}  coverage",
        "name",
        "verdict",
        "selected",
        "eligible",
        "SSA-lowered",
        "transformed",
        "relocated",
        "rejected"
    );
    let row = |name: &str, verdict: &str, c: &Coverage| {
        let total = c.ssa_lowered + c.relocated + c.rejected;
        let pct = if total > 0 {
            100.0 * c.ssa_lowered as f64 / total as f64
        } else {
            0.0
        };
        println!(
            "          {name:<24} {verdict:<7}  {:>8} {:>8} {:>11} {:>11} {:>9} {:>8}  {}/{total} ({pct:.1}%)",
            c.selected,
            c.eligible,
            c.ssa_lowered,
            c.transformed,
            c.relocated,
            c.rejected,
            c.ssa_lowered
        );
        if !c.actual_intensity.is_empty() {
            println!("          actual intensity: {:?}", c.actual_intensity);
        }
    };
    for m in &cov.members {
        row(&m.name, if m.passed { "PASS" } else { "FAIL" }, &m.coverage);
        for diagnostic in &m.diagnostics {
            println!("          {}: {diagnostic}", m.name);
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use kamy_core::SymbolId;

    #[test]
    fn numeric_rva_parsing_rejects_overflow_instead_of_truncating() {
        assert_eq!(parse_rva("0xffffffff").unwrap(), Rva::new(u32::MAX));
        assert!(parse_rva("0x100000000").is_err());
        assert!(parse_rvas("1000,140001000").is_err());
        assert_eq!(
            parse_rvas("0x1000, 2000").unwrap(),
            [Rva::new(0x1000), Rva::new(0x2000)]
        );
    }

    #[test]
    fn corpus_coverage_uses_successful_linker_outcomes_not_requested_passes() {
        let symbols = [0x1000, 0x2000, 0x3000].map(|rva| SymbolId::Host { rva: Rva::new(rva) });
        let report = kamy_link::Report {
            moved: symbols[..2].to_vec(),
            ssa_lowered: 2,
            ssa_lowered_symbols: symbols[..2].to_vec(),
            functions: vec![
                kamy_link::FunctionReport {
                    symbol: symbols[0].clone(),
                    selected: true,
                    eligible: true,
                    lowered: true,
                    transformed: true,
                    intensity: 0.5,
                    allocation: None,
                },
                kamy_link::FunctionReport {
                    symbol: symbols[1].clone(),
                    selected: true,
                    eligible: true,
                    lowered: true,
                    transformed: false,
                    intensity: 0.0,
                    allocation: None,
                },
                kamy_link::FunctionReport {
                    symbol: symbols[2].clone(),
                    selected: true,
                    eligible: false,
                    lowered: false,
                    transformed: false,
                    intensity: 0.0,
                    allocation: None,
                },
            ],
            ..Default::default()
        };
        let coverage = report_to_coverage(&report);
        assert_eq!(coverage.selected, 3);
        assert_eq!(coverage.eligible, 2);
        assert_eq!(coverage.ssa_lowered, 2);
        assert_eq!(coverage.transformed, 1);
        assert_eq!(coverage.relocated, 0);
        assert_eq!(
            coverage.actual_intensity,
            BTreeMap::from([("0".into(), 1), ("0.5".into(), 1)])
        );
    }
}
