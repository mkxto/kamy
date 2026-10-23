//! Golden behavior records (`expected.yml`) and the mismatch diff.

use std::path::Path;

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

use crate::manifest::MemberKind;

/// SSA lift/lower coverage for one member, or an accumulated corpus total.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Coverage {
    #[serde(default)]
    pub selected: usize,
    #[serde(default)]
    pub eligible: usize,
    #[serde(default)]
    pub transformed: usize,
    /// Successful lowering intensity histogram; zero includes semantic identity.
    #[serde(default)]
    pub actual_intensity: std::collections::BTreeMap<String, usize>,
    /// Functions lowered through the SSA pipeline — the only "covered" bucket.
    pub ssa_lowered: usize,
    /// Functions shipped as verbatim relocations (no SSA) — not covered.
    pub relocated: usize,
    /// Functions rejected with a reason — not covered.
    pub rejected: usize,
    pub by_reason: std::collections::BTreeMap<String, usize>,
}

impl Coverage {
    /// Fold `other` into `self`: sum the counts and merge the by-reason tallies.
    pub fn merge(&mut self, other: &Coverage) {
        self.selected += other.selected;
        self.eligible += other.eligible;
        self.transformed += other.transformed;
        for (intensity, count) in &other.actual_intensity {
            *self.actual_intensity.entry(intensity.clone()).or_default() += count;
        }
        self.ssa_lowered += other.ssa_lowered;
        self.relocated += other.relocated;
        self.rejected += other.rejected;
        for (reason, count) in &other.by_reason {
            *self.by_reason.entry(reason.clone()).or_default() += count;
        }
    }
}

/// One observed run of a console/gui member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunObservation {
    pub run: u32,
    pub exit: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    #[serde(default)]
    pub trace: Vec<String>,
}

/// One invoked export of a dll member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DllResult {
    pub call: String,
    pub ret: String,
}

/// Blessing provenance metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    pub os: String,
    pub arch: String,
    #[serde(default)]
    pub toolchains: std::collections::BTreeMap<String, String>,
    pub blessed_utc: String,
    pub kamy_sha: String,
}

/// Captured observable behavior of a single member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BehaviorRecord {
    pub oracle: MemberKind,
    #[serde(default)]
    pub runs: u32,
    #[serde(default)]
    pub observations: Vec<RunObservation>,
    #[serde(default)]
    pub results: Vec<DllResult>,
    #[serde(default)]
    pub provenance: Option<Provenance>,
}

impl BehaviorRecord {
    /// Require a complete, nonempty observation set for the declared oracle.
    pub fn validate(&self) -> Result<()> {
        match self.oracle {
            MemberKind::Console | MemberKind::Gui => {
                anyhow::ensure!(self.runs > 0, "no execution vectors recorded");
                anyhow::ensure!(
                    self.observations.len() == self.runs as usize,
                    "declared {} runs but recorded {} observations",
                    self.runs,
                    self.observations.len()
                );
                anyhow::ensure!(
                    self.results.is_empty(),
                    "non-DLL oracle contains DLL results"
                );
                for (index, observation) in self.observations.iter().enumerate() {
                    anyhow::ensure!(
                        observation.run as usize == index,
                        "run index expected {index}, observed {}",
                        observation.run
                    );
                    anyhow::ensure!(
                        observation.exit.is_some(),
                        "run {index} has no termination result"
                    );
                    if self.oracle == MemberKind::Gui {
                        anyhow::ensure!(
                            !observation.trace.is_empty()
                                && observation.trace.iter().all(|line| !line.trim().is_empty()),
                            "run {index} has no usable GUI trace"
                        );
                    }
                }
            }
            MemberKind::Dll => {
                anyhow::ensure!(self.runs == 0, "DLL oracle declares console runs");
                anyhow::ensure!(
                    self.observations.is_empty(),
                    "DLL oracle contains console runs"
                );
                anyhow::ensure!(!self.results.is_empty(), "no DLL calls recorded");
                for result in &self.results {
                    let valid_call = result
                        .call
                        .split_once('(')
                        .is_some_and(|(name, args)| !name.trim().is_empty() && args.ends_with(')'));
                    anyhow::ensure!(valid_call, "malformed DLL call {:?}", result.call);
                    anyhow::ensure!(
                        matches!(result.ret.as_str(), "true" | "false")
                            || result.ret.parse::<i64>().is_ok()
                            || result.ret.parse::<u64>().is_ok(),
                        "call {} has no valid return value: {:?}",
                        result.call,
                        result.ret
                    );
                }
            }
        }
        Ok(())
    }

    /// Load a golden record from YAML.
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let record: Self =
            serde_norway::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        record
            .validate()
            .with_context(|| format!("invalid {}", path.display()))?;
        Ok(record)
    }

    /// Serialize this record to YAML at `path`.
    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate().context("invalid behavior record")?;
        let text = serde_norway::to_string(self).context("serializing behavior record")?;
        std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))
    }
}

/// Human-readable mismatch lines between `expected` and `observed`.
/// Empty result == PASS. Provenance is ignored in the comparison.
#[must_use]
pub fn diff(expected: &BehaviorRecord, observed: &BehaviorRecord) -> Vec<String> {
    let mut out = Vec::new();
    for (label, record) in [("expected", expected), ("observed", observed)] {
        if let Err(error) = record.validate() {
            out.push(format!("{label} observation invalid: {error:#}"));
        }
    }
    if !out.is_empty() {
        return out;
    }

    if expected.oracle != observed.oracle {
        out.push(format!(
            "oracle: expected {:?}, observed {:?}",
            expected.oracle, observed.oracle
        ));
        return out;
    }

    match expected.oracle {
        MemberKind::Console | MemberKind::Gui => {
            if expected.observations.len() != observed.observations.len() {
                out.push(format!(
                    "run count: expected {}, observed {}",
                    expected.observations.len(),
                    observed.observations.len()
                ));
            }
            for (e, o) in expected
                .observations
                .iter()
                .zip(observed.observations.iter())
            {
                if e.exit != o.exit {
                    out.push(format!(
                        "run {}: exit expected {:?}, observed {:?}",
                        e.run, e.exit, o.exit
                    ));
                }
                if e.stdout != o.stdout {
                    out.push(format!("run {}: stdout differs", e.run));
                }
                if e.stderr != o.stderr {
                    out.push(format!("run {}: stderr differs", e.run));
                }
                if e.trace != o.trace {
                    out.push(format!("run {}: trace differs", e.run));
                }
            }
        }
        MemberKind::Dll => {
            if expected.results.len() != observed.results.len() {
                out.push(format!(
                    "result count: expected {}, observed {}",
                    expected.results.len(),
                    observed.results.len()
                ));
            }
            for (e, o) in expected.results.iter().zip(observed.results.iter()) {
                if e.call != o.call {
                    out.push(format!("call: expected {}, observed {}", e.call, o.call));
                } else if e.ret != o.ret {
                    out.push(format!(
                        "call {}: ret expected {}, observed {}",
                        e.call, e.ret, o.ret
                    ));
                }
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn console_record() -> BehaviorRecord {
        BehaviorRecord {
            oracle: MemberKind::Console,
            runs: 1,
            observations: vec![RunObservation {
                run: 0,
                exit: Some(17),
                stdout: "answer\n".into(),
                stderr: String::new(),
                trace: Vec::new(),
            }],
            results: Vec::new(),
            provenance: None,
        }
    }

    fn dll_record() -> BehaviorRecord {
        BehaviorRecord {
            oracle: MemberKind::Dll,
            runs: 0,
            observations: Vec::new(),
            results: vec![DllResult {
                call: "argument(1,2,3,4,5,6)".into(),
                ret: "5".into(),
            }],
            provenance: None,
        }
    }

    #[test]
    fn equal_empty_observations_are_not_a_pass() {
        for oracle in [MemberKind::Console, MemberKind::Gui, MemberKind::Dll] {
            let empty = BehaviorRecord {
                oracle,
                runs: 0,
                observations: Vec::new(),
                results: Vec::new(),
                provenance: None,
            };
            assert!(!diff(&empty, &empty).is_empty());
        }
    }

    #[test]
    fn incomplete_and_misindexed_runs_are_not_comparable() {
        let mut malformed = console_record();
        malformed.runs = 2;
        assert!(!diff(&malformed, &malformed).is_empty());
        malformed = console_record();
        malformed.observations[0].run = 1;
        assert!(!diff(&malformed, &malformed).is_empty());
        malformed = console_record();
        malformed.observations[0].exit = None;
        assert!(!diff(&malformed, &malformed).is_empty());
    }

    #[test]
    fn gui_requires_actual_trace_observations() {
        let mut record = console_record();
        record.oracle = MemberKind::Gui;
        assert!(!diff(&record, &record).is_empty());
        record.observations[0].trace.push(" ".into());
        assert!(!diff(&record, &record).is_empty());
        record.observations[0].trace = vec!["MessageBoxW:hello".into()];
        assert!(diff(&record, &record).is_empty());
        let mut changed = record.clone();
        changed.observations[0].trace[0] = "MessageBoxW:wrong".into();
        assert!(
            diff(&record, &changed)
                .iter()
                .any(|line| line.contains("trace differs"))
        );
    }

    #[test]
    fn failed_or_missing_dll_results_are_not_values() {
        for ret in ["", " ", "<loader-failed exit 5>", "5\n6", "not-a-value"] {
            let mut record = dll_record();
            record.results[0].ret = ret.into();
            assert!(!diff(&record, &record).is_empty());
        }
        let mut record = dll_record();
        record.results[0].call.clear();
        assert!(!diff(&record, &record).is_empty());
    }

    #[test]
    fn valid_nonzero_and_dll_values_still_compare_exactly() {
        let console = console_record();
        assert!(diff(&console, &console).is_empty());
        let mut changed = console.clone();
        changed.observations[0].stdout = "wrong\n".into();
        assert!(
            diff(&console, &changed)
                .iter()
                .any(|line| line.contains("stdout differs"))
        );
        let dll = dll_record();
        assert!(diff(&dll, &dll).is_empty());
        let mut changed = dll.clone();
        changed.results[0].ret = "6".into();
        assert!(
            diff(&dll, &changed)
                .iter()
                .any(|line| line.contains("ret expected 5, observed 6"))
        );
    }

    #[test]
    fn coverage_merges_execution_independent_semantic_outcomes() {
        let mut total = Coverage {
            selected: 3,
            eligible: 2,
            ssa_lowered: 2,
            transformed: 1,
            actual_intensity: BTreeMap::from([("0.5".into(), 1), ("0".into(), 1)]),
            rejected: 1,
            by_reason: BTreeMap::from([("RegisterPressure".into(), 1)]),
            ..Default::default()
        };
        total.merge(&Coverage {
            selected: 4,
            eligible: 3,
            ssa_lowered: 3,
            transformed: 0,
            actual_intensity: BTreeMap::from([("0".into(), 3)]),
            rejected: 1,
            by_reason: BTreeMap::from([("LiftFailure".into(), 1)]),
            ..Default::default()
        });
        assert_eq!(
            (
                total.selected,
                total.eligible,
                total.ssa_lowered,
                total.transformed
            ),
            (7, 5, 5, 1)
        );
        assert_eq!(
            total.actual_intensity,
            BTreeMap::from([("0".into(), 4), ("0.5".into(), 1)])
        );
        assert_eq!(total.rejected, 2);
        assert_eq!(total.relocated, 0);
        let serialized = serde_norway::to_string(&total).unwrap();
        let restored: Coverage = serde_norway::from_str(&serialized).unwrap();
        assert_eq!(restored.transformed, 1);
        assert_eq!(restored.actual_intensity, total.actual_intensity);
        assert_eq!(restored.by_reason, total.by_reason);
    }

    #[test]
    fn historical_identity_coverage_never_fabricates_semantic_protection() {
        let coverage: Coverage = serde_norway::from_str(
            "ssa_lowered: 1314\nrelocated: 0\nrejected: 9888\nby_reason: {}\n",
        )
        .unwrap();
        assert_eq!(coverage.ssa_lowered, 1314);
        assert_eq!(coverage.rejected, 9888);
        assert_eq!(coverage.transformed, 0);
        assert!(coverage.actual_intensity.is_empty());
    }
}
