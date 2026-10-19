//! Test-vector equivalence and differential self-test harness.

use anyhow::Context as _;

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

/// Aggregate result of a differential run between two binaries.
pub struct DiffReport {
    pub runs: u32,
    pub mismatches: Vec<Mismatch>,
}

impl DiffReport {
    /// PASS iff no observable differences were recorded.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.mismatches.is_empty()
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

struct RunResult {
    exit: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run(binary: &Path, input: &[u8]) -> std::io::Result<RunResult> {
    let mut child = Command::new(binary)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    // Write before reading: feed the whole payload then drop stdin to signal EOF.
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input)?;
    }

    let output = child.wait_with_output()?;
    Ok(RunResult {
        exit: output.status.code(),
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

fn show_code(code: Option<i32>) -> String {
    code.map_or_else(|| "<signal>".to_string(), |c| c.to_string())
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
/// observable behavior (exit code + stdout). Run 0 uses empty stdin; later
/// runs feed a deterministic seeded random payload so input-consuming binaries
/// are exercised. PASS = empty [`DiffReport::mismatches`].
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
        let input = if run_idx == 0 {
            Vec::new()
        } else {
            let mut rng = SplitMix64(seed.wrapping_add(u64::from(run_idx)));
            // 1..=256 bytes, deterministically sized per run.
            let len = 1 + (rng.next_u64() % 256) as usize;
            let mut buf = vec![0u8; len];
            rng.fill(&mut buf);
            buf
        };

        let a = run(original, &input).with_context(|| format!("running {}", original.display()))?;
        let b =
            run(protected, &input).with_context(|| format!("running {}", protected.display()))?;

        if a.exit != b.exit {
            mismatches.push(Mismatch {
                run: run_idx,
                field: "exit".to_string(),
                original: show_code(a.exit),
                protected: show_code(b.exit),
            });
        }
        if a.stdout != b.stdout {
            mismatches.push(Mismatch {
                run: run_idx,
                field: "stdout".to_string(),
                original: preview(&a.stdout),
                protected: preview(&b.stdout),
            });
        }
        if a.stderr != b.stderr {
            mismatches.push(Mismatch {
                run: run_idx,
                field: "stderr".to_string(),
                original: preview(&a.stderr),
                protected: preview(&b.stderr),
            });
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    // Avoid spawning the test harness itself (would recurse); exercise the
    // dependency-free pieces instead and leave live-PE diffing to orchestrator
    // smoke, per AGENTS.md cross-platform rule.

    #[test]
    fn splitmix_is_deterministic() {
        let mut a = SplitMix64(0xDEAD_BEEF);
        let mut b = SplitMix64(0xDEAD_BEEF);
        let mut c = SplitMix64(0xDEAD_BEF0);
        assert_eq!(a.next_u64(), b.next_u64());
        assert_ne!(SplitMix64(0xDEAD_BEEF).next_u64(), c.next_u64());
    }

    #[test]
    fn fill_covers_partial_tail() {
        let mut rng = SplitMix64(1);
        let mut buf = [0u8; 13];
        rng.fill(&mut buf);
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn empty_report_passes() {
        let report = DiffReport {
            runs: 4,
            mismatches: Vec::new(),
        };
        assert!(report.passed());
        let report = DiffReport {
            runs: 1,
            mismatches: vec![Mismatch {
                run: 0,
                field: "exit".to_string(),
                original: "0".to_string(),
                protected: "1".to_string(),
            }],
        };
        assert!(!report.passed());
    }
}
