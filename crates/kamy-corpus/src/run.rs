//! Observe a built binary and produce a [`BehaviorRecord`]; bless and verify.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail};

use crate::build::{build_member, toolchain_versions};
use crate::manifest::{Member, MemberKind};
use crate::record::{BehaviorRecord, Coverage, DllResult, Provenance, RunObservation};

/// Observe `bin` according to `member`'s oracle kind.
fn observe(member: &Member, bin: &Path, seed: u64) -> Result<BehaviorRecord> {
    match member.kind {
        MemberKind::Console => observe_console(member, bin, seed, false),
        MemberKind::Gui => observe_console(member, bin, seed, true),
        MemberKind::Dll => observe_dll(member, bin),
    }
}

fn observe_console(member: &Member, bin: &Path, seed: u64, gui: bool) -> Result<BehaviorRecord> {
    let runs = member.vectors.max(1);
    let mut observations = Vec::with_capacity(runs as usize);

    for run_idx in 0..runs {
        let input = kamy_verify::seeded_input(seed, run_idx);
        let (exit, stdout, stderr, trace) = if gui {
            run_with_trace(bin, &input, member, run_idx)?
        } else {
            let (exit, out, err) = kamy_verify::run_capture(bin, &input)
                .with_context(|| format!("running {}", bin.display()))?;
            (exit, out, err, Vec::new())
        };
        observations.push(RunObservation {
            run: run_idx,
            exit,
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

type TracedRun = (Option<i32>, Vec<u8>, Vec<u8>, Vec<String>);

/// Run a gui member with a per-run `KAMY_TRACE` sink and collect its lines.
fn run_with_trace(bin: &Path, input: &[u8], member: &Member, run_idx: u32) -> Result<TracedRun> {
    use std::io::Write as _;

    let trace_file = std::env::temp_dir().join(format!(
        "kamy-trace-{}-{}-{}.txt",
        member.name,
        std::process::id(),
        run_idx
    ));
    let _ = std::fs::remove_file(&trace_file);

    let mut child = Command::new(bin)
        .env("KAMY_TRACE", &trace_file)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("running {}", bin.display()))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input)?;
    }
    let output = child.wait_with_output()?;

    let trace = match std::fs::read_to_string(&trace_file) {
        Ok(text) => text.lines().map(ToString::to_string).collect(),
        Err(_) => Vec::new(),
    };
    let _ = std::fs::remove_file(&trace_file);

    Ok((output.status.code(), output.stdout, output.stderr, trace))
}

fn observe_dll(member: &Member, bin: &Path) -> Result<BehaviorRecord> {
    let loader = loader_path().context("locating kamy-loader")?;
    let dll = bin
        .canonicalize()
        .with_context(|| format!("resolving {}", bin.display()))?;

    let mut results = Vec::with_capacity(member.exports.len());
    for export in &member.exports {
        let mut cmd = Command::new(&loader);
        cmd.arg(&dll).arg(&export.name).arg(&export.ret);
        for a in &export.args {
            cmd.arg(a);
        }
        let output = cmd
            .output()
            .with_context(|| format!("spawning loader for {}", export.name))?;
        anyhow::ensure!(
            output.status.success(),
            "loader failed for {}::{}",
            member.name,
            export.name
        );
        let ret = String::from_utf8_lossy(&output.stdout).trim().to_string();
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
    let bin = build_member(member, root)?
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
/// `protect(original, protected_tmp)` applies the kamy transform and returns its
/// SSA lift/lower [`Coverage`]. Returns the mismatch lines (empty == PASS) and
/// the member's coverage; coverage is reported even when the diff diverges.
pub fn verify_member(
    member: &Member,
    root: &Path,
    seed: u64,
    protect: &dyn Fn(&Path, &Path) -> Result<Coverage>,
) -> Result<(Vec<String>, Coverage)> {
    let original = build_member(member, root)?
        .with_context(|| format!("member {} has no original binary", member.name))?;

    let expected_path = member.expected_path();
    if !expected_path.is_file() {
        return Ok((
            vec![format!("member {} is unblessed", member.name)],
            Coverage::default(),
        ));
    }
    let expected = BehaviorRecord::load(&expected_path)?;

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
    let coverage = protect(&original, &protected)
        .with_context(|| format!("protecting member {}", member.name))?;

    let observed = observe(member, &protected, seed)?;
    let _ = std::fs::remove_file(&protected);

    Ok((crate::record::diff(&expected, &observed), coverage))
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
