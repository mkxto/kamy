//! `kamy bisect`: delta-debug an SSA-lowering regression to a minimal culprit.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context as _, bail};

pub(crate) fn run(
    input: &Path,
    expect_exit: i32,
    stdin_file: Option<&Path>,
    expect_stdout: Option<&Path>,
    timeout: u64,
    keep: bool,
) -> anyhow::Result<()> {
    let stdin = match stdin_file {
        Some(p) => std::fs::read(p).with_context(|| format!("reading {}", p.display()))?,
        None => Vec::new(),
    };
    let expected_stdout = match expect_stdout {
        Some(p) => Some(std::fs::read(p).with_context(|| format!("reading {}", p.display()))?),
        None => None,
    };
    let run_options = kamy_run::RunOptions {
        exe: input.into(),
        stdin,
        timeout: Duration::from_secs(timeout),
        ..Default::default()
    };
    let is_pass = |protected: &Path| -> anyhow::Result<bool> {
        let mut options = run_options.clone();
        options.exe = protected.into();
        let out = kamy_run::run_traced(&options)?;
        Ok(matches_oracle(
            &out,
            expect_exit,
            expected_stdout.as_deref(),
        ))
    };

    let outcome = kamy_triage::bisect(input, &run_options, &is_pass, keep)?;
    if matches_oracle(&outcome.replay, expect_exit, expected_stdout.as_deref()) {
        if let Some(path) = &outcome.artifact {
            std::fs::remove_file(path)
                .with_context(|| format!("removing non-failing replay {}", path.display()))?;
            let directory = path.parent().context("retained replay has no directory")?;
            std::fs::remove_dir(directory).with_context(|| {
                format!(
                    "removing non-failing replay directory {}",
                    directory.display()
                )
            })?;
        }
        bail!("final traced replay passes the probe oracle; failure did not reproduce");
    }

    println!("candidates: {}", outcome.candidates);
    println!("steps:      {}", outcome.steps);
    if outcome.culprit.is_empty() {
        println!("culprit:    <none>");
    } else {
        println!("culprit:");
        for rva in &outcome.culprit {
            println!("  {rva}");
        }
    }
    if let Some(path) = &outcome.artifact {
        println!("artifact:   {}", path.display());
    }
    if outcome.replay.timed_out {
        println!("replay:     timed out");
    }
    if let Some(f) = outcome.replay.fault {
        println!(
            "fault: code={:#x} address={:#x} rva={:#x}",
            f.code, f.address, f.rva
        );
    }

    if let Some(culprit) = outcome.culprit.first() {
        eprintln!(
            "→ deep-dive the culprit in x64dbg; inspect: kamy dump {} --rva {:#x} --stage regalloc",
            input.display(),
            culprit.get()
        );
    }
    Ok(())
}

fn matches_oracle(out: &kamy_run::RunOutcome, expect_exit: i32, stdout: Option<&[u8]>) -> bool {
    kamy_verify::validate_outcome(out, Some(expect_exit)).is_ok()
        && stdout.is_none_or(|want| out.stdout.trim_ascii_end() == want.trim_ascii_end())
}

#[cfg(test)]
mod tests {
    use super::matches_oracle;
    use kamy_run::{Fault, RunOutcome};

    #[test]
    fn replay_oracle_rejects_wrong_values_and_incomplete_runs() {
        let mut out = RunOutcome {
            exit_code: Some(0),
            stdout: b"42\r\n".to_vec(),
            ..Default::default()
        };
        assert!(matches_oracle(&out, 0, Some(b"42\n")));
        assert!(!matches_oracle(&out, 0, Some(b"43\n")));
        assert!(!matches_oracle(&out, 1, Some(b"42\n")));
        out.timed_out = true;
        assert!(!matches_oracle(&out, 0, Some(b"42\n")));
        out.timed_out = false;
        out.exit_code = None;
        assert!(!matches_oracle(&out, 0, Some(b"42\n")));
    }

    #[test]
    fn replay_oracle_honors_explicit_negative_exit_contract() {
        let code = 0xc000_0005u32 as i32;
        let mut out = RunOutcome {
            exit_code: Some(code),
            stdout: b"expected\n".to_vec(),
            ..Default::default()
        };
        assert!(matches_oracle(&out, code, Some(b"expected")));
        assert!(!matches_oracle(&out, 0, Some(b"expected")));
        out.fault = Some(Fault {
            code: code as u32,
            address: 0x1234,
            image_base: 0x1000,
            rva: 0x234,
        });
        assert!(matches_oracle(&out, code, Some(b"expected")));
        assert!(!matches_oracle(&out, code, Some(b"wrong")));
        assert!(!matches_oracle(&out, 0, None));
        out.exit_code = None;
        assert!(matches_oracle(&out, code, Some(b"expected")));
        out.timed_out = true;
        assert!(!matches_oracle(&out, code, Some(b"expected")));
    }
}
