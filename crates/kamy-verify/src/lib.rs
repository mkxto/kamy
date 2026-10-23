//! Test-vector equivalence and differential self-test harness.

use anyhow::{Context as _, Result};

use std::path::Path;
use std::time::Duration;

use kamy_run::{RunOptions, RunOutcome, run_traced};

/// Wall-clock cap applied to every corpus/differential launch so a hung or
/// crashed target is killed instead of stalling the harness.
const RUN_TIMEOUT: Duration = Duration::from_secs(30);

/// Aggregate result of a differential run between two binaries.
pub struct DiffReport {
    pub runs: u32,
    pub mismatches: Vec<Mismatch>,
}

impl DiffReport {
    /// PASS iff at least one input was exercised and every observation was valid
    /// and equal.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.runs > 0 && self.mismatches.is_empty()
    }
}

/// A single observed behavioral divergence for one input vector.
pub struct Mismatch {
    pub run: u32,
    pub field: String,
    pub original: String,
    pub protected: String,
}

/// splitmix64: deterministic, dependency-free PRNG for input payloads.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let word = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
    }
}

/// Spawn `binary`, feed `input` on stdin, and retain execution health as well as
/// output. Tracing distinguishes unhandled faults from ordinary nonzero exits.
pub fn run_capture(binary: &Path, input: &[u8]) -> Result<RunOutcome> {
    let opts = RunOptions {
        exe: binary.to_path_buf(),
        stdin: input.to_vec(),
        timeout: RUN_TIMEOUT,
        ..RunOptions::default()
    };
    run_traced(&opts).with_context(|| format!("running {}", binary.display()))
}

/// Reject incomplete execution and unexpected unhandled faults. Ordinary
/// nonzero exits are valid unless an exact `expected_exit` was declared.
/// An observed fault is a terminal event even if the runner stopped before
/// collecting an exit code; only an explicit matching expectation accepts it.
/// Returns the observed exit or declared fault code without changing `outcome`.
pub fn validate_outcome(outcome: &RunOutcome, expected_exit: Option<i32>) -> Result<i32> {
    anyhow::ensure!(!outcome.timed_out, "execution timed out");
    if let Some(fault) = outcome.fault {
        let code = fault.code as i32;
        anyhow::ensure!(
            expected_exit == Some(code),
            "unexpected unhandled fault {} at {:#x}",
            fault.code,
            fault.address
        );
        if let Some(exit) = outcome.exit_code {
            anyhow::ensure!(
                exit == code,
                "fault termination {code} disagrees with exit {exit}"
            );
        }
        return Ok(code);
    }
    let exit = outcome
        .exit_code
        .context("execution has no termination result")?;
    if let Some(expected) = expected_exit {
        anyhow::ensure!(
            exit == expected,
            "exit expected {expected}, observed {exit}"
        );
    }
    Ok(exit)
}

/// Deterministic stdin payload for run index `run` under `seed`. Run 0 is empty;
/// later runs yield the seeded splitmix64 payload of 1..=256 bytes.
#[must_use]
pub fn seeded_input(seed: u64, run: u32) -> Vec<u8> {
    if run == 0 {
        return Vec::new();
    }
    let mut rng = SplitMix64(seed.wrapping_add(u64::from(run)));
    // 1..=256 bytes, deterministically sized per run.
    let len = 1 + (rng.next_u64() % 256) as usize;
    let mut buf = vec![0u8; len];
    rng.fill(&mut buf);
    buf
}

fn show_code(code: Option<i32>) -> String {
    code.map_or_else(|| "<no exit code>".to_string(), |c| c.to_string())
}

/// Lossy, bounded preview of a byte stream for mismatch reporting.
fn preview(bytes: &[u8]) -> String {
    const LIMIT: usize = 64;
    let shown = &bytes[..bytes.len().min(LIMIT)];
    let mut out = String::from_utf8_lossy(shown).into_owned();
    if bytes.len() > LIMIT {
        out.push_str("...");
    }
    format!("{} bytes: {out:?}", bytes.len())
}

/// Run `original` and `protected` against identical inputs and diff their
/// observable behavior (exit code, stdout, stderr). Run 0 uses empty stdin;
/// later runs feed a deterministic seeded random payload. PASS requires valid
/// execution on both sides and no differences on every input.
pub fn differential(
    original: &Path,
    protected: &Path,
    vectors: u32,
    seed: u64,
) -> anyhow::Result<DiffReport> {
    let _s = tracing::info_span!("verify").entered();
    let runs = vectors.max(1);
    let mut mismatches = Vec::new();

    for run_idx in 0..runs {
        let input = seeded_input(seed, run_idx);

        let original_outcome = run_capture(original, &input)
            .with_context(|| format!("running {}", original.display()))?;
        let protected_outcome = run_capture(protected, &input)
            .with_context(|| format!("running {}", protected.display()))?;
        compare_outcomes(
            run_idx,
            &original_outcome,
            &protected_outcome,
            &mut mismatches,
        );
    }

    let report = DiffReport { runs, mismatches };
    for m in &report.mismatches {
        tracing::warn!(
            run = m.run,
            field = %m.field,
            original = %m.original,
            protected = %m.protected,
            "behavioral divergence"
        );
    }
    tracing::info!(
        runs,
        mismatches = report.mismatches.len(),
        "differential complete"
    );
    Ok(report)
}

fn compare_outcomes(
    run: u32,
    original: &RunOutcome,
    protected: &RunOutcome,
    mismatches: &mut Vec<Mismatch>,
) {
    let original_health = validate_outcome(original, None);
    let protected_health = validate_outcome(protected, None);
    if original_health.is_err() || protected_health.is_err() {
        mismatches.push(Mismatch {
            run,
            field: "execution".to_string(),
            original: original_health.map_or_else(|e| e.to_string(), |_| "valid".to_string()),
            protected: protected_health.map_or_else(|e| e.to_string(), |_| "valid".to_string()),
        });
    }
    if original.exit_code != protected.exit_code {
        mismatches.push(Mismatch {
            run,
            field: "exit".to_string(),
            original: show_code(original.exit_code),
            protected: show_code(protected.exit_code),
        });
    }
    for (field, a, b) in [
        ("stdout", &original.stdout, &protected.stdout),
        ("stderr", &original.stderr, &protected.stderr),
    ] {
        if a != b {
            mismatches.push(Mismatch {
                run,
                field: field.to_string(),
                original: preview(a),
                protected: preview(b),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normal_exit(exit: i32) -> RunOutcome {
        RunOutcome {
            exit_code: Some(exit),
            stdout: b"answer\n".to_vec(),
            ..RunOutcome::default()
        }
    }

    fn faulted() -> RunOutcome {
        RunOutcome {
            fault: Some(kamy_run::Fault {
                code: 0xE000_1234,
                address: 0x1000,
                image_base: 0x1000,
                rva: 0,
            }),
            ..RunOutcome::default()
        }
    }

    #[test]
    fn normal_nonzero_exit_is_not_a_fault() {
        for exit in [0, 17, -17, 0xE000_1234_u32 as i32] {
            assert_eq!(validate_outcome(&normal_exit(exit), None).unwrap(), exit);
            assert_eq!(
                validate_outcome(&normal_exit(exit), Some(exit)).unwrap(),
                exit
            );
            assert!(validate_outcome(&normal_exit(exit), Some(exit.wrapping_add(1))).is_err());
        }
    }

    #[test]
    fn fault_requires_explicit_matching_expectation() {
        let mut outcome = faulted();
        let code = outcome.fault.unwrap().code as i32;
        assert!(validate_outcome(&outcome, None).is_err());
        assert!(validate_outcome(&outcome, Some(0)).is_err());
        assert_eq!(validate_outcome(&outcome, Some(code)).unwrap(), code);
        assert_eq!(outcome.exit_code, None);
        outcome.exit_code = Some(code);
        assert_eq!(validate_outcome(&outcome, Some(code)).unwrap(), code);
        outcome.exit_code = Some(0);
        assert!(validate_outcome(&outcome, Some(code)).is_err());
    }

    #[test]
    fn timeout_and_missing_termination_are_never_valid() {
        let mut outcome = normal_exit(0);
        outcome.timed_out = true;
        assert!(validate_outcome(&outcome, None).is_err());
        assert!(validate_outcome(&outcome, Some(0)).is_err());
        assert!(validate_outcome(&RunOutcome::default(), None).is_err());
        let mut outcome = faulted();
        outcome.timed_out = true;
        assert!(validate_outcome(&outcome, Some(0xE000_1234_u32 as i32)).is_err());
    }

    #[test]
    fn equal_invalid_children_cannot_pass_differential() {
        let mut timed_out = normal_exit(0);
        timed_out.timed_out = true;
        for outcome in [timed_out, faulted(), RunOutcome::default()] {
            let mut mismatches = Vec::new();
            compare_outcomes(0, &outcome, &outcome, &mut mismatches);
            assert!(mismatches.iter().any(|m| m.field == "execution"));
            assert!(
                !DiffReport {
                    runs: 1,
                    mismatches,
                }
                .passed()
            );
            let valid = normal_exit(0);
            for (a, b) in [(&outcome, &valid), (&valid, &outcome)] {
                let mut mismatches = Vec::new();
                compare_outcomes(0, a, b, &mut mismatches);
                assert!(mismatches.iter().any(|m| m.field == "execution"));
            }
        }
    }

    #[test]
    fn differential_accepts_equal_nonzero_and_detects_wrong_values() {
        let original = normal_exit(17);
        let mut protected = normal_exit(17);
        let mut mismatches = Vec::new();
        compare_outcomes(0, &original, &protected, &mut mismatches);
        assert!(
            DiffReport {
                runs: 1,
                mismatches,
            }
            .passed()
        );
        protected.stdout = b"wrong\n".to_vec();
        protected.stderr = b"diagnostic\n".to_vec();
        protected.exit_code = Some(18);
        let mut mismatches = Vec::new();
        compare_outcomes(0, &original, &protected, &mut mismatches);
        assert_eq!(
            mismatches
                .iter()
                .map(|m| m.field.as_str())
                .collect::<Vec<_>>(),
            ["exit", "stdout", "stderr"]
        );
    }

    #[test]
    fn no_vectors_is_not_a_passing_report() {
        assert!(
            !DiffReport {
                runs: 0,
                mismatches: Vec::new(),
            }
            .passed()
        );
    }
}
