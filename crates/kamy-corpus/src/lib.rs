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

/// Fixed default seed so observations are reproducible across invocations.
pub const DEFAULT_SEED: u64 = 0xC0FF_EE15_D31B_A5E5;

/// Build every member's original binary.
pub fn build_corpus(dir: &Path) -> Result<()> {
    let members = load_corpus(dir)?;
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

/// Bless each member: build, observe twice, stamp provenance, save `expected.yml`.
pub fn bless_corpus(dir: &Path) -> Result<()> {
    let members = load_corpus(dir)?;
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
                tracing::error!(error = %e, "bless failed");
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
/// accumulate SSA lift/lower coverage. Coverage is captured for every member
/// regardless of PASS/FAIL. The returned [`CorpusCoverage`] carries both axes;
/// the caller decides how to surface the failure count (see `kamy corpus verify`).
pub fn verify_corpus(
    dir: &Path,
    protect: &dyn Fn(&Path, &Path) -> Result<Coverage>,
    opts: &VerifyOptions,
) -> Result<CorpusCoverage> {
    let mut members = load_corpus(dir)?;
    if let Some(name) = &opts.member {
        if !members.iter().any(|m| &m.name == name) {
            anyhow::bail!("unknown member {name}");
        }
        members.retain(|m| &m.name == name);
    }
    let (mut passed, mut failed) = (0u32, 0u32);
    let mut total = Coverage::default();
    let mut per_member = Vec::with_capacity(members.len());
    for member in &members {
        let _s = tracing::info_span!("member", name = %member.name).entered();
        let (mismatches, coverage) =
            run::verify_member(member, dir, DEFAULT_SEED, protect, opts.keep)?;
        let member_passed = mismatches.is_empty();
        if member_passed {
            passed += 1;
            tracing::info!("PASS");
        } else {
            failed += 1;
            for m in &mismatches {
                tracing::warn!(mismatch = %m, "divergence");
            }
            tracing::error!(mismatches = mismatches.len(), "FAIL");
        }
        tracing::info!(
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
        });
    }
    tracing::info!(
        members = members.len(),
        passed,
        failed,
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

/// Oracle/ABI self-check across the corpus on each member's UNPROTECTED
/// original: assert the oracle is deterministic and reproduces its own golden.
/// Nothing is protected; this isolates oracle/ABI bugs from protector bugs.
pub fn doctor_corpus(dir: &Path) -> Result<DoctorReport> {
    let members = load_corpus(dir)?;
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
    let members = load_corpus(dir)?;
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
