//! Observe a built binary and produce a [`BehaviorRecord`]; bless and verify.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Wall-clock cap for every observed child launch (same budget as the
/// differential harness) so a hung or crashed target is torn down.
const RUN_TIMEOUT: Duration = Duration::from_secs(30);

use anyhow::{Context as _, Result, bail};

use crate::build::{build_member, toolchain_versions};
use crate::manifest::{Member, MemberKind};
use crate::record::{BehaviorRecord, Coverage, DllResult, Provenance, RunObservation};

/// Observe `bin` according to `member`'s oracle kind.
fn observe(member: &Member, bin: &Path, seed: u64) -> Result<BehaviorRecord> {
    let record = match member.kind {
        MemberKind::Console => observe_console(member, bin, seed, false),
        MemberKind::Gui => observe_console(member, bin, seed, true),
        MemberKind::Dll => observe_dll(member, bin),
    }?;
    validate_record(member, &record)?;
    Ok(record)
}

fn observe_console(member: &Member, bin: &Path, seed: u64, gui: bool) -> Result<BehaviorRecord> {
    let runs = member.vectors.max(1);
    let mut observations = Vec::with_capacity(runs as usize);

    for run_idx in 0..runs {
        let input = kamy_verify::seeded_input(seed, run_idx);
        let (outcome, trace) = if gui {
            run_with_trace(bin, &input, member, run_idx)?
        } else {
            let outcome = kamy_verify::run_capture(bin, &input)
                .with_context(|| format!("running {}", bin.display()))?;
            (outcome, Vec::new())
        };
        let exit = kamy_verify::validate_outcome(&outcome, member.expected_exit)
            .with_context(|| format!("member {} run {run_idx}", member.name))?;
        let kamy_run::RunOutcome { stdout, stderr, .. } = outcome;
        observations.push(RunObservation {
            run: run_idx,
            exit: Some(exit),
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            trace,
        });
    }

    Ok(BehaviorRecord {
        oracle: member.kind,
        runs,
        observations,
        results: Vec::new(),
        provenance: None,
    })
}

type TracedRun = (kamy_run::RunOutcome, Vec<String>);

/// Run a gui member with a per-run `KAMY_TRACE` sink and collect its lines.
fn run_with_trace(bin: &Path, input: &[u8], member: &Member, run_idx: u32) -> Result<TracedRun> {
    let trace_file = std::env::temp_dir().join(format!(
        "kamy-trace-{}-{}-{}.txt",
        member.name,
        std::process::id(),
        run_idx
    ));
    let _ = std::fs::remove_file(&trace_file);

    let opts = kamy_run::RunOptions {
        exe: bin.to_path_buf(),
        stdin: input.to_vec(),
        env: vec![(
            "KAMY_TRACE".to_string(),
            trace_file.to_string_lossy().into_owned(),
        )],
        timeout: RUN_TIMEOUT,
        ..kamy_run::RunOptions::default()
    };
    let outcome = kamy_run::run_traced(&opts).with_context(|| format!("running {}", bin.display()));
    let trace = std::fs::read_to_string(&trace_file)
        .with_context(|| format!("member {} run {run_idx}: reading GUI trace", member.name));
    let _ = std::fs::remove_file(&trace_file);

    Ok((outcome?, trace?.lines().map(ToString::to_string).collect()))
}

fn observe_dll(member: &Member, bin: &Path) -> Result<BehaviorRecord> {
    anyhow::ensure!(
        !member.exports.is_empty(),
        "member {} declares no DLL calls",
        member.name
    );
    if let Some(exit) = member.expected_exit {
        anyhow::ensure!(
            exit == 0,
            "DLL loader protocol requires expected_exit 0, not {exit}"
        );
    }
    let loader = loader_path().context("locating kamy-loader")?;
    let dll = bin
        .canonicalize()
        .with_context(|| format!("resolving {}", bin.display()))?;

    let mut results = Vec::with_capacity(member.exports.len());
    for export in &member.exports {
        let mut args = vec![
            dll.to_string_lossy().into_owned(),
            export.name.clone(),
            export.ret.clone(),
        ];
        args.extend(export.args.iter().cloned());
        let opts = kamy_run::RunOptions {
            exe: loader.clone(),
            args,
            timeout: RUN_TIMEOUT,
            ..kamy_run::RunOptions::default()
        };
        let outcome = kamy_run::run_traced(&opts)
            .with_context(|| format!("spawning loader for {}", export.name))?;
        let ret = loader_result(&outcome, &export.ret).with_context(|| {
            format!(
                "member {} call {}({})",
                member.name,
                export.name,
                export.args.join(",")
            )
        })?;
        results.push(DllResult {
            call: format!("{}({})", export.name, export.args.join(",")),
            ret,
        });
    }

    Ok(BehaviorRecord {
        oracle: member.kind,
        runs: 0,
        observations: Vec::new(),
        results,
        provenance: None,
    })
}

fn loader_result(outcome: &kamy_run::RunOutcome, retkind: &str) -> Result<String> {
    anyhow::ensure!(
        outcome.fault.is_none(),
        "DLL loader suffered an unhandled fault"
    );
    kamy_verify::validate_outcome(outcome, Some(0)).context("DLL loader execution failed")?;
    let value = std::str::from_utf8(&outcome.stdout)
        .context("DLL loader result is not UTF-8")?
        .trim();
    validate_return(retkind, value)?;
    Ok(value.to_string())
}

fn validate_return(retkind: &str, value: &str) -> Result<()> {
    let valid = match retkind {
        "i32" => value.parse::<i32>().is_ok(),
        "u32" => value.parse::<u32>().is_ok(),
        "i64" => value.parse::<i64>().is_ok(),
        "u64" => value.parse::<u64>().is_ok(),
        "bool" => matches!(value, "true" | "false"),
        other => bail!("unsupported DLL return kind {other:?}"),
    };
    anyhow::ensure!(
        valid,
        "missing or malformed DLL {retkind} result: {value:?}"
    );
    Ok(())
}

fn validate_record(member: &Member, record: &BehaviorRecord) -> Result<()> {
    record
        .validate()
        .with_context(|| format!("member {} oracle", member.name))?;
    anyhow::ensure!(
        record.oracle == member.kind,
        "member {} oracle kind disagrees with manifest",
        member.name
    );
    match member.kind {
        MemberKind::Console | MemberKind::Gui => {
            anyhow::ensure!(
                record.runs == member.vectors.max(1),
                "member {} expected {} vectors, recorded {}",
                member.name,
                member.vectors.max(1),
                record.runs
            );
            if let Some(expected) = member.expected_exit {
                for observation in &record.observations {
                    anyhow::ensure!(
                        observation.exit == Some(expected),
                        "member {} run {}: exit expected {expected}, recorded {:?}",
                        member.name,
                        observation.run,
                        observation.exit
                    );
                }
            }
        }
        MemberKind::Dll => {
            if let Some(exit) = member.expected_exit {
                anyhow::ensure!(
                    exit == 0,
                    "DLL loader protocol requires expected_exit 0, not {exit}"
                );
            }
            anyhow::ensure!(
                !member.exports.is_empty() && record.results.len() == member.exports.len(),
                "member {} DLL call set disagrees with manifest",
                member.name
            );
            for (export, result) in member.exports.iter().zip(&record.results) {
                let call = format!("{}({})", export.name, export.args.join(","));
                anyhow::ensure!(
                    result.call == call,
                    "DLL call expected {call}, recorded {}",
                    result.call
                );
                validate_return(&export.ret, &result.ret)
                    .with_context(|| format!("member {} call {call}", member.name))?;
            }
        }
    }
    Ok(())
}

fn loader_path() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("resolving current exe")?;
    let dir = exe.parent().context("current exe has no parent")?;
    let name = if cfg!(windows) {
        "kamy-loader.exe"
    } else {
        "kamy-loader"
    };
    let path = dir.join(name);
    anyhow::ensure!(
        path.is_file(),
        "kamy-loader not found at {}",
        path.display()
    );
    Ok(path)
}

/// Bless the original: build, observe twice for determinism, stamp, and save.
pub fn bless_member(member: &Member, root: &Path, seed: u64) -> Result<BehaviorRecord> {
    let bin = build_member(member, root, false)?
        .with_context(|| format!("member {} could not be built", member.name))?;

    let first = observe(member, &bin, seed)?;
    let second = observe(member, &bin, seed)?;
    if first != second {
        bail!(
            "member {} is non-deterministic; quarantine (observations diverge across identical runs)",
            member.name
        );
    }

    let mut record = first;
    record.provenance = Some(provenance());
    record.save(&member.expected_path())?;
    Ok(record)
}

/// Verify the protected binary against the golden record.
/// `protect(member, original, protected_tmp)` applies the kamy transform and returns its
/// SSA lift/lower [`Coverage`] plus required-lowering diagnostics. Returns all diagnostics
/// (empty == PASS) and the member's coverage, including on requirement or observation failure.
pub fn verify_member(
    member: &Member,
    root: &Path,
    seed: u64,
    protect: &crate::MemberProtector<'_>,
    keep: bool,
) -> Result<(Vec<String>, Coverage)> {
    let original = build_member(member, root, false)?
        .with_context(|| format!("member {} has no original binary", member.name))?;

    let expected_path = member.expected_path();
    if !expected_path.is_file() {
        return Ok((
            vec![format!("member {} is unblessed", member.name)],
            Coverage::default(),
        ));
    }
    let expected = BehaviorRecord::load(&expected_path)?;
    validate_record(member, &expected)?;

    let ext = original
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("bin");
    let protected_dir = root.join("protected");
    std::fs::create_dir_all(&protected_dir)
        .with_context(|| format!("creating {}", protected_dir.display()))?;
    let protected = protected_dir.join(format!(
        "kamy-protected-{}-{}.{ext}",
        member.name,
        std::process::id()
    ));
    let protection = protect(member, &original, &protected)
        .with_context(|| format!("protecting member {}", member.name));
    if protection.is_err() && !keep {
        let _ = std::fs::remove_file(&protected);
    }
    let (coverage, mut diagnostics) = protection?;

    // A failed lowering obligation already fails this member; do not execute its output.
    if diagnostics.is_empty() {
        match observe(member, &protected, seed) {
            Ok(observed) => diagnostics.extend(crate::record::diff(&expected, &observed)),
            Err(error) => diagnostics.push(format!(
                "member {} observation failed: {error:#}",
                member.name
            )),
        }
    }
    if keep {
        tracing::info!(path = %protected.display(), "kept protected artifact");
    } else {
        let _ = std::fs::remove_file(&protected);
    }

    Ok((diagnostics, coverage))
}

/// Oracle/ABI self-check for one member on its UNPROTECTED original: observe it
/// twice to assert determinism, then diff the observation against its golden to
/// assert the oracle reproduces its own baseline (catches ABI/oracle bugs such
/// as a dropped call argument). Never protects the binary. Returns
/// `(ok, messages)` where `ok` means every check passed.
pub fn doctor_member(member: &Member, root: &Path, seed: u64) -> Result<(bool, Vec<String>)> {
    let mut messages = Vec::new();

    let built = match build_member(member, root, false) {
        Ok(built) => built,
        Err(error) => {
            return Ok((
                false,
                vec![format!("member {} build failed: {error:#}", member.name)],
            ));
        }
    };
    let bin = match built {
        Some(bin) => bin,
        None => {
            messages.push(format!("member {} could not be built", member.name));
            return Ok((false, messages));
        }
    };

    let first = match observe(member, &bin, seed) {
        Ok(record) => record,
        Err(error) => {
            return Ok((
                false,
                vec![format!(
                    "member {} original observation failed: {error:#}",
                    member.name
                )],
            ));
        }
    };
    let second = match observe(member, &bin, seed) {
        Ok(record) => record,
        Err(error) => {
            return Ok((
                false,
                vec![format!(
                    "member {} repeated original observation failed: {error:#}",
                    member.name
                )],
            ));
        }
    };
    if first != second {
        messages.push("non-deterministic: observations diverge across identical runs".to_string());
    }

    let expected_path = member.expected_path();
    if expected_path.is_file() {
        let expected = match BehaviorRecord::load(&expected_path).and_then(|record| {
            validate_record(member, &record)?;
            Ok(record)
        }) {
            Ok(record) => record,
            Err(error) => {
                messages.push(format!("member {} invalid golden: {error:#}", member.name));
                return Ok((false, messages));
            }
        };
        let golden_diff = crate::record::diff(&expected, &first);
        if !golden_diff.is_empty() {
            messages.push(
                "oracle does not reproduce its golden on the unprotected original".to_string(),
            );
            messages.extend(golden_diff);
        }
    } else {
        messages.push("unblessed: no golden record to check against".to_string());
    }

    Ok((messages.is_empty(), messages))
}

fn provenance() -> Provenance {
    let kamy_sha = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    Provenance {
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        toolchains: toolchain_versions(),
        blessed_utc: rfc3339_now(),
        kamy_sha,
    }
}

/// Minimal UTC RFC 3339 timestamp from the system clock (no date dependency).
fn rfc3339_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86_400;
    let tod = secs % 86_400;
    let (hh, mm, ss) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    let (y, mo, d) = civil_from_days(days as i64);
    format!("{y:04}-{mo:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Howard Hinnant's days-to-civil algorithm (days since 1970-01-01).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kamy_run::{Fault, RunOutcome};

    fn loader_success(value: &[u8]) -> RunOutcome {
        RunOutcome {
            exit_code: Some(0),
            stdout: value.to_vec(),
            ..RunOutcome::default()
        }
    }

    #[test]
    fn loader_requires_successful_execution_and_actual_typed_output() {
        assert_eq!(
            loader_result(&loader_success(b"18446744073709551615\n"), "u64").unwrap(),
            "18446744073709551615"
        );
        assert_eq!(
            loader_result(&loader_success(b"-17\n"), "i32").unwrap(),
            "-17"
        );
        assert_eq!(
            loader_result(&loader_success(b"true\n"), "bool").unwrap(),
            "true"
        );
        for value in [
            b"".as_slice(),
            b" \n",
            b"<loader-failed exit 5>",
            b"5\n6",
            b"\xff",
        ] {
            assert!(loader_result(&loader_success(value), "u64").is_err());
        }
        assert!(loader_result(&loader_success(b"-1\n"), "u64").is_err());
        assert!(loader_result(&loader_success(b"4294967296\n"), "u32").is_err());
        assert!(loader_result(&loader_success(b"1\n"), "bool").is_err());
        assert!(loader_result(&loader_success(b"1\n"), "unknown").is_err());
    }

    #[test]
    fn loader_failure_is_never_a_comparable_return() {
        let mut outcome = loader_success(b"5\n");
        outcome.exit_code = Some(5);
        assert!(loader_result(&outcome, "u64").is_err());
        outcome.exit_code = None;
        assert!(loader_result(&outcome, "u64").is_err());
        outcome.exit_code = Some(0);
        outcome.timed_out = true;
        assert!(loader_result(&outcome, "u64").is_err());
        outcome.timed_out = false;
        outcome.fault = Some(Fault {
            code: 0,
            address: 1,
            image_base: 0,
            rva: 1,
        });
        assert!(loader_result(&outcome, "u64").is_err());
    }

    fn console_member() -> Member {
        serde_norway::from_str("kind: console\nvectors: 1\n").unwrap()
    }

    fn console_record(exit: i32) -> BehaviorRecord {
        BehaviorRecord {
            oracle: MemberKind::Console,
            runs: 1,
            observations: vec![RunObservation {
                run: 0,
                exit: Some(exit),
                stdout: "answer".into(),
                stderr: String::new(),
                trace: Vec::new(),
            }],
            results: Vec::new(),
            provenance: None,
        }
    }

    #[test]
    fn manifest_expectation_is_distinct_from_normal_nonzero_exit() {
        let mut member = console_member();
        let record = console_record(-17);
        assert!(validate_record(&member, &record).is_ok());
        member.expected_exit = Some(-17);
        assert!(validate_record(&member, &record).is_ok());
        member.expected_exit = Some(0);
        assert!(validate_record(&member, &record).is_err());
        member.expected_exit = None;
        member.vectors = 2;
        assert!(validate_record(&member, &record).is_err());
    }

    #[test]
    fn dll_record_must_cover_exact_declared_calls_and_types() {
        let mut member: Member = serde_norway::from_str(
            "kind: dll\nexports:\n  - name: argument\n    ret: u64\n    args: ['u64:1', 'u64:2', 'u64:3', 'u64:4', 'u64:5', 'u64:6']\n  - name: argument\n    ret: u64\n    args: ['u64:1', 'u64:2', 'u64:3', 'u64:4', 'u64:6', 'u64:5']\n",
        ).unwrap();
        let record = BehaviorRecord {
            oracle: MemberKind::Dll,
            runs: 0,
            observations: Vec::new(),
            results: member
                .exports
                .iter()
                .zip(["5", "6"])
                .map(|(export, ret)| DllResult {
                    call: format!("{}({})", export.name, export.args.join(",")),
                    ret: ret.into(),
                })
                .collect(),
            provenance: None,
        };
        assert!(validate_record(&member, &record).is_ok());
        let mut malformed = record.clone();
        malformed.results.pop();
        assert!(validate_record(&member, &malformed).is_err());
        malformed = record.clone();
        malformed.results.swap(0, 1);
        assert!(validate_record(&member, &malformed).is_err());
        malformed = record.clone();
        malformed.results[0].ret = "-1".into();
        assert!(validate_record(&member, &malformed).is_err());
        member.expected_exit = Some(5);
        assert!(validate_record(&member, &record).is_err());
        member.expected_exit = None;
        member.exports.clear();
        assert!(validate_record(&member, &record).is_err());
    }
}
