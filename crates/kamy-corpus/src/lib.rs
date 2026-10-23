//! Differential corpus engine: build, bless, verify, and list corpus members.

pub mod build;
pub mod manifest;
pub mod record;
pub mod run;

use std::path::Path;

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

pub use manifest::{Export, Member, MemberKind, load_corpus};
pub use record::{BehaviorRecord, Coverage, DllResult, Provenance, RunObservation, diff};

/// A member protection operation returning coverage and unmet lowering obligations.
pub type MemberProtector<'a> =
    dyn Fn(&Member, &Path, &Path) -> Result<(Coverage, Vec<String>)> + 'a;

/// Fixed default seed so observations are reproducible across invocations.
pub const DEFAULT_SEED: u64 = 0xC0FF_EE15_D31B_A5E5;

/// Load the actual campaign before performing work, rejecting empty or unknown selections.
fn campaign_members(dir: &Path, selected: Option<&str>) -> Result<Vec<Member>> {
    let mut members = load_corpus(dir)?;
    if let Some(name) = selected {
        members.retain(|member| member.name == name);
        anyhow::ensure!(!members.is_empty(), "unknown member {name}");
    }
    anyhow::ensure!(
        !members.is_empty(),
        "corpus {} contains no members",
        dir.display()
    );
    Ok(members)
}

/// Build every member's original binary.
pub fn build_corpus(dir: &Path) -> Result<()> {
    let members = campaign_members(dir, None)?;
    let (mut built, mut skipped) = (0u32, 0u32);
    for member in &members {
        let _s = tracing::info_span!("member", name = %member.name).entered();
        match build::build_member(member, dir, true)? {
            Some(path) => {
                built += 1;
                tracing::info!(path = %path.display(), "built");
            }
            None => {
                skipped += 1;
                tracing::warn!("skipped (toolchain unavailable)");
            }
        }
    }
    tracing::info!(members = members.len(), built, skipped, "build complete");
    Ok(())
}

/// Bless selected originals: build, observe twice, stamp provenance, save `expected.yml`.
pub fn bless_corpus(dir: &Path, member: Option<&str>) -> Result<()> {
    let members = campaign_members(dir, member)?;
    let (mut blessed, mut failed) = (0u32, 0u32);
    for member in &members {
        let _s = tracing::info_span!("member", name = %member.name).entered();
        match run::bless_member(member, dir, DEFAULT_SEED) {
            Ok(_) => {
                blessed += 1;
                tracing::info!("blessed");
            }
            Err(e) => {
                failed += 1;
                tracing::warn!(error = %e, "bless failed");
            }
        }
    }
    tracing::info!(members = members.len(), blessed, failed, "bless complete");
    if failed > 0 {
        anyhow::bail!("{failed} member(s) failed to bless");
    }
    Ok(())
}

/// Per-member SSA coverage paired with its pass/fail verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberCoverage {
    pub name: String,
    pub passed: bool,
    pub coverage: Coverage,
    /// Behavioral mismatches and required-lowering/execution/protection errors, preserved on failure.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<String>,
}

/// Aggregated verification outcome: per-member coverage plus the corpus total.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CorpusCoverage {
    pub members: Vec<MemberCoverage>,
    pub total: Coverage,
    pub passed: u32,
    pub failed: u32,
}

impl CorpusCoverage {
    /// Serialize this coverage baseline to YAML at `path`.
    pub fn save(&self, path: &Path) -> Result<()> {
        let text = serde_norway::to_string(self).context("serializing corpus coverage")?;
        std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))
    }

    /// Load a coverage baseline from YAML at `path`.
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        serde_norway::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }
}

/// Human-readable lines describing how `new` coverage differs from `old`:
/// members whose PASS/FAIL verdict flipped, whose `ssa_lowered`/`rejected`
/// counts moved, members added or removed, and corpus-total reason-count
/// deltas. Empty == identical.
#[must_use]
pub fn coverage_delta(old: &CorpusCoverage, new: &CorpusCoverage) -> Vec<String> {
    use std::collections::{BTreeMap, BTreeSet};

    let mut out = Vec::new();
    let old_members: BTreeMap<&str, &MemberCoverage> =
        old.members.iter().map(|m| (m.name.as_str(), m)).collect();
    let new_members: BTreeMap<&str, &MemberCoverage> =
        new.members.iter().map(|m| (m.name.as_str(), m)).collect();

    for (name, nm) in &new_members {
        match old_members.get(name) {
            None => out.push(format!(
                "{name}: new member ({})",
                if nm.passed { "PASS" } else { "FAIL" }
            )),
            Some(om) => {
                if om.passed != nm.passed {
                    out.push(format!(
                        "{name}: {} -> {}",
                        if om.passed { "PASS" } else { "FAIL" },
                        if nm.passed { "PASS" } else { "FAIL" }
                    ));
                }
                if om.coverage.ssa_lowered != nm.coverage.ssa_lowered {
                    out.push(format!(
                        "{name}: ssa_lowered {} -> {}",
                        om.coverage.ssa_lowered, nm.coverage.ssa_lowered
                    ));
                }
                if om.coverage.rejected != nm.coverage.rejected {
                    out.push(format!(
                        "{name}: rejected {} -> {}",
                        om.coverage.rejected, nm.coverage.rejected
                    ));
                }
                for (axis, old_count, new_count) in [
                    ("selected", om.coverage.selected, nm.coverage.selected),
                    ("eligible", om.coverage.eligible, nm.coverage.eligible),
                    (
                        "transformed",
                        om.coverage.transformed,
                        nm.coverage.transformed,
                    ),
                ] {
                    if old_count != new_count {
                        out.push(format!("{name}: {axis} {old_count} -> {new_count}"));
                    }
                }
                if om.coverage.actual_intensity != nm.coverage.actual_intensity {
                    out.push(format!(
                        "{name}: actual_intensity {:?} -> {:?}",
                        om.coverage.actual_intensity, nm.coverage.actual_intensity
                    ));
                }
            }
        }
    }
    for name in old_members.keys() {
        if !new_members.contains_key(name) {
            out.push(format!("{name}: removed"));
        }
    }

    let mut reasons: BTreeSet<&str> = BTreeSet::new();
    reasons.extend(old.total.by_reason.keys().map(String::as_str));
    reasons.extend(new.total.by_reason.keys().map(String::as_str));
    for reason in reasons {
        let o = old.total.by_reason.get(reason).copied().unwrap_or(0);
        let n = new.total.by_reason.get(reason).copied().unwrap_or(0);
        if o != n {
            out.push(format!("reason {reason}: {o} -> {n}"));
        }
    }

    out
}

/// Scope and artifact-retention knobs for [`verify_corpus`].
#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    /// When `Some`, verify only the named member (error if unknown).
    pub member: Option<String>,
    /// When `true`, keep the protected artifact on disk instead of deleting it.
    pub keep: bool,
}

/// Verify each member: protect the original, diff against its golden record, and
/// accumulate SSA lift/lower coverage. The callback returns the actual report's
/// coverage plus required-lowering diagnostics, which fail the member without
/// discarding its coverage. The returned [`CorpusCoverage`] carries both axes;
/// the caller decides how to surface the failure count (see `kamy corpus verify`).
pub fn verify_corpus(
    dir: &Path,
    protect: &MemberProtector<'_>,
    opts: &VerifyOptions,
) -> Result<CorpusCoverage> {
    let members = campaign_members(dir, opts.member.as_deref())?;
    let (mut passed, mut failed) = (0u32, 0u32);
    let mut total = Coverage::default();
    let mut per_member = Vec::with_capacity(members.len());
    for member in &members {
        let _s = tracing::info_span!("member", name = %member.name).entered();
        let (mismatches, coverage) =
            match run::verify_member(member, dir, DEFAULT_SEED, protect, opts.keep) {
                Ok(result) => result,
                Err(error) => (vec![format!("{error:#}")], Coverage::default()),
            };
        let member_passed = mismatches.is_empty();
        if member_passed {
            passed += 1;
            tracing::info!("PASS");
        } else {
            failed += 1;
            for m in &mismatches {
                tracing::warn!(mismatch = %m, "divergence");
            }
            tracing::warn!(mismatches = mismatches.len(), "FAIL");
        }
        tracing::info!(
            selected = coverage.selected,
            eligible = coverage.eligible,
            transformed = coverage.transformed,
            actual_intensity = ?coverage.actual_intensity,
            ssa_lowered = coverage.ssa_lowered,
            relocated = coverage.relocated,
            rejected = coverage.rejected,
            "coverage"
        );
        total.merge(&coverage);
        per_member.push(MemberCoverage {
            name: member.name.clone(),
            passed: member_passed,
            coverage,
            diagnostics: mismatches,
        });
    }
    tracing::info!(
        members = members.len(),
        passed,
        failed,
        selected = total.selected,
        eligible = total.eligible,
        transformed = total.transformed,
        actual_intensity = ?total.actual_intensity,
        ssa_lowered = total.ssa_lowered,
        relocated = total.relocated,
        rejected = total.rejected,
        "verify complete"
    );
    for (reason, count) in &total.by_reason {
        tracing::info!(reason = %reason, count, "reject summary");
    }
    Ok(CorpusCoverage {
        members: per_member,
        total,
        passed,
        failed,
    })
}

/// Per-member result of [`doctor_corpus`]: name, overall OK, and diagnostics.
#[derive(Debug, Clone, Default)]
pub struct DoctorReport {
    pub members: Vec<(String, bool, Vec<String>)>,
}

/// Oracle/ABI self-check across the selected members' UNPROTECTED originals:
/// assert the oracle is deterministic and reproduces its own golden.
/// Nothing is protected; this isolates oracle/ABI bugs from protector bugs.
pub fn doctor_corpus(dir: &Path, member: Option<&str>) -> Result<DoctorReport> {
    let members = campaign_members(dir, member)?;
    let mut out = Vec::with_capacity(members.len());
    for member in &members {
        let _s = tracing::info_span!("doctor", name = %member.name).entered();
        let (ok, messages) = run::doctor_member(member, dir, DEFAULT_SEED)?;
        if ok {
            tracing::info!("OK");
        } else {
            for m in &messages {
                tracing::warn!(msg = %m, "doctor");
            }
        }
        out.push((member.name.clone(), ok, messages));
    }
    tracing::info!(members = members.len(), "doctor complete");
    Ok(DoctorReport { members: out })
}

/// List corpus members and their declared oracle kinds.
pub fn list_corpus(dir: &Path) -> Result<()> {
    let members = campaign_members(dir, None)?;
    for member in &members {
        println!(
            "{:<24} {:?}  toolchain={:<9} vectors={} exports={}",
            member.name,
            member.kind,
            member.toolchain.as_deref().unwrap_or("-"),
            member.vectors,
            member.exports.len()
        );
    }
    tracing::info!(members = members.len(), "listed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestCorpus(std::path::PathBuf);

    impl TestCorpus {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "kamy-campaign-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn member(&self, name: &str) -> std::path::PathBuf {
            let dir = self.0.join("members").join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("meta.yml"),
                "kind: console\nprebuilt: absent.exe\n",
            )
            .unwrap();
            dir
        }
    }

    impl Drop for TestCorpus {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn empty_campaign_cannot_report_success_for_any_command() {
        let corpus = TestCorpus::new();
        assert!(build_corpus(&corpus.0).is_err());
        assert!(bless_corpus(&corpus.0, None).is_err());
        assert!(doctor_corpus(&corpus.0, None).is_err());
        assert!(list_corpus(&corpus.0).is_err());
        assert!(
            verify_corpus(
                &corpus.0,
                &|_, _, _| unreachable!(),
                &VerifyOptions::default()
            )
            .is_err()
        );
    }

    #[test]
    fn selection_rejects_unknown_and_scopes_blessing_population() {
        let corpus = TestCorpus::new();
        let first = corpus.member("first");
        let second = corpus.member("second");
        std::fs::write(first.join("expected.yml"), "first golden").unwrap();
        std::fs::write(second.join("expected.yml"), "second golden").unwrap();
        let selected = campaign_members(&corpus.0, Some("second")).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].dir, second);
        assert!(bless_corpus(&corpus.0, Some("missing")).is_err());
        assert!(doctor_corpus(&corpus.0, Some("missing")).is_err());
        let opts = VerifyOptions {
            member: Some("missing".into()),
            keep: false,
        };
        assert!(verify_corpus(&corpus.0, &|_, _, _| unreachable!(), &opts).is_err());
        // A selected original which cannot be observed must not rewrite any other golden.
        assert!(bless_corpus(&corpus.0, Some("second")).is_err());
        assert_eq!(
            std::fs::read_to_string(first.join("expected.yml")).unwrap(),
            "first golden"
        );
        assert_eq!(
            std::fs::read_to_string(second.join("expected.yml")).unwrap(),
            "second golden"
        );
    }

    #[test]
    fn selected_doctor_skips_quarantined_originals_and_preserves_goldens() {
        let corpus = TestCorpus::new();
        let quarantined = corpus.member("quarantined");
        let selected = corpus.member("selected");
        std::fs::write(quarantined.join("expected.yml"), "quarantined golden").unwrap();
        std::fs::write(selected.join("expected.yml"), "selected golden").unwrap();

        // Neither original exists: doctor must diagnose only the requested member,
        // without trying to rebuild or rebless the quarantined member.
        let report = doctor_corpus(&corpus.0, Some("selected")).unwrap();
        assert_eq!(report.members.len(), 1);
        let (name, ok, diagnostics) = &report.members[0];
        assert_eq!(name, "selected");
        assert!(!ok);
        assert!(
            diagnostics
                .iter()
                .any(|message| message.contains("build failed"))
        );
        assert!(!quarantined.join("absent.exe").exists());
        assert_eq!(
            std::fs::read_to_string(quarantined.join("expected.yml")).unwrap(),
            "quarantined golden"
        );
        assert_eq!(
            std::fs::read_to_string(selected.join("expected.yml")).unwrap(),
            "selected golden"
        );
    }

    #[test]
    fn observation_failure_keeps_report_coverage_in_campaign_and_saved_baseline() {
        let corpus = TestCorpus::new();
        let dir = corpus.member("observation_failure");
        std::fs::write(dir.join("absent.exe"), "original fixture").unwrap();
        BehaviorRecord {
            oracle: MemberKind::Console,
            runs: 1,
            observations: vec![RunObservation {
                run: 0,
                exit: Some(0),
                stdout: String::new(),
                stderr: String::new(),
                trace: Vec::new(),
            }],
            results: Vec::new(),
            provenance: None,
        }
        .save(&dir.join("expected.yml"))
        .unwrap();

        // No protected file is produced: observation fails without executing a binary.
        let result = verify_corpus(
            &corpus.0,
            &|_, _, _| {
                Ok((
                    Coverage {
                        selected: 3,
                        eligible: 2,
                        ssa_lowered: 2,
                        rejected: 1,
                        by_reason: [("fixture-rejection".into(), 1)].into_iter().collect(),
                        ..Default::default()
                    },
                    Vec::new(),
                ))
            },
            &VerifyOptions::default(),
        )
        .unwrap();
        assert_eq!(result.failed, 1);
        assert_eq!(result.passed, 0);
        assert!(!result.members[0].passed);
        assert!(
            result.members[0]
                .diagnostics
                .iter()
                .any(|message| { message.contains("observation_failure observation failed") })
        );
        assert_eq!(result.total.selected, 3);
        assert_eq!(result.total.ssa_lowered, 2);
        assert_eq!(result.total.rejected, 1);
        assert_eq!(result.total.by_reason["fixture-rejection"], 1);

        let baseline = corpus.0.join("coverage.yml");
        result.save(&baseline).unwrap();
        let saved = CorpusCoverage::load(&baseline).unwrap();
        assert_eq!(saved.total.selected, 3);
        assert_eq!(saved.total.ssa_lowered, 2);
        assert_eq!(saved.total.rejected, 1);
        assert_eq!(saved.total.by_reason["fixture-rejection"], 1);
        assert_eq!(saved.members[0].coverage.selected, 3);
        assert_eq!(saved.members[0].diagnostics, result.members[0].diagnostics);
        assert_eq!(saved.failed, 1);
    }

    #[test]
    fn campaign_keeps_later_members_after_an_individual_failure() {
        let corpus = TestCorpus::new();
        corpus.member("first");
        corpus.member("second");
        let result = verify_corpus(
            &corpus.0,
            &|_, _, _| unreachable!(),
            &VerifyOptions::default(),
        )
        .unwrap();
        assert_eq!(result.failed, 2);
        assert_eq!(result.passed, 0);
        assert_eq!(
            result
                .members
                .iter()
                .map(|member| member.name.as_str())
                .collect::<Vec<_>>(),
            ["first", "second"]
        );
        assert!(
            result
                .members
                .iter()
                .all(|member| !member.diagnostics.is_empty())
        );
    }

    #[test]
    fn baseline_delta_keeps_execution_and_semantic_coverage_separate() {
        let member = |transformed, intensity: &str| MemberCoverage {
            name: "portable".into(),
            passed: true,
            diagnostics: Vec::new(),
            coverage: Coverage {
                selected: 3,
                eligible: 2,
                ssa_lowered: 2,
                transformed,
                rejected: 1,
                actual_intensity: [(intensity.into(), 2)].into_iter().collect(),
                ..Default::default()
            },
        };
        let old = CorpusCoverage {
            members: vec![member(0, "0")],
            passed: 1,
            ..Default::default()
        };
        let new = CorpusCoverage {
            members: vec![member(2, "0.5")],
            passed: 1,
            ..Default::default()
        };
        let delta = coverage_delta(&old, &new);
        assert!(
            delta
                .iter()
                .any(|line| line == "portable: transformed 0 -> 2")
        );
        assert!(
            delta
                .iter()
                .any(|line| line.starts_with("portable: actual_intensity"))
        );
        assert!(
            !delta
                .iter()
                .any(|line| line.contains("ssa_lowered") || line.contains("PASS ->"))
        );
    }
}
