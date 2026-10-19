//! Differential corpus engine: build, bless, verify, and list corpus members.

pub mod build;
pub mod manifest;
pub mod record;
pub mod run;

use std::path::Path;

use anyhow::Result;

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
#[derive(Debug, Clone)]
pub struct MemberCoverage {
    pub name: String,
    pub passed: bool,
    pub coverage: Coverage,
}

/// Aggregated verification outcome: per-member coverage plus the corpus total.
#[derive(Debug, Clone, Default)]
pub struct CorpusCoverage {
    pub members: Vec<MemberCoverage>,
    pub total: Coverage,
    pub passed: u32,
    pub failed: u32,
}

/// Verify each member: protect the original, diff against its golden record, and
/// accumulate SSA lift/lower coverage. Coverage is captured for every member
/// regardless of PASS/FAIL. The returned [`CorpusCoverage`] carries both axes;
/// the caller decides how to surface the failure count (see `kamy corpus verify`).
pub fn verify_corpus(
    dir: &Path,
    protect: &dyn Fn(&Path, &Path) -> Result<Coverage>,
) -> Result<CorpusCoverage> {
    let members = load_corpus(dir)?;
    let (mut passed, mut failed) = (0u32, 0u32);
    let mut total = Coverage::default();
    let mut per_member = Vec::with_capacity(members.len());
    for member in &members {
        let _s = tracing::info_span!("member", name = %member.name).entered();
        let (mismatches, coverage) = run::verify_member(member, dir, DEFAULT_SEED, protect)?;
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
