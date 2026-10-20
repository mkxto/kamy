//! Build driver: compile each member's original binary from source.
//!
//! All toolchain invocation is Windows-only and `#[cfg(windows)]`-gated so the
//! crate still compiles when targeting other platforms.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::manifest::Member;

/// Build (or locate) the original binary for `member`.
///
/// Returns the binary path, or `Ok(None)` when the member is skipped because its
/// toolchain (e.g. `clang-cl`) is unavailable. `prebuilt` members return the
/// committed path without building.
/// With `force`, always rebuild from source; otherwise reuse an existing
/// original so `bless`/`verify` need no toolchain (D34).
pub fn build_member(member: &Member, corpus_root: &Path, force: bool) -> Result<Option<PathBuf>> {
    if member.prebuilt.is_some() {
        let path = member.binary_path();
        anyhow::ensure!(
            path.is_file(),
            "prebuilt binary missing: {}",
            path.display()
        );
        return Ok(Some(path));
    }
    let out = member.binary_path();
    if !force && out.is_file() {
        return Ok(Some(out));
    }
    build_from_source(member, corpus_root)
}

/// Best-effort toolchain version strings for provenance stamping.
#[must_use]
pub fn toolchain_versions() -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    #[cfg(windows)]
    {
        if let Some(v) = win::rustc_version() {
            map.insert("rustc".to_string(), v);
        }
        if let Some(v) = win::cl_version() {
            map.insert("msvc".to_string(), v);
        }
    }
    map
}

#[cfg(not(windows))]
fn build_from_source(_member: &Member, _corpus_root: &Path) -> Result<Option<PathBuf>> {
    anyhow::bail!("corpus build requires Windows")
}

#[cfg(windows)]
fn build_from_source(member: &Member, corpus_root: &Path) -> Result<Option<PathBuf>> {
    win::build(member, corpus_root)
}

#[cfg(windows)]
mod win {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use anyhow::{Context as _, Result, bail};

    use super::Member;
    use crate::manifest::MemberKind;

    pub(super) fn build(member: &Member, corpus_root: &Path) -> Result<Option<PathBuf>> {
        let source = member
            .source
            .as_ref()
            .context("member without prebuilt must set `source`")?;
        let source_path = member.dir.join(source);
        anyhow::ensure!(
            source_path.is_file(),
            "source missing: {}",
            source_path.display()
        );

        let out = member.binary_path();
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }

        let toolchain = member.toolchain.as_deref().unwrap_or("msvc");
        match toolchain {
            "rustc" => build_rustc(member, &source_path, &out)?,
            "msvc" => {
                if build_cl(member, corpus_root, &source_path, &out, "cl")?.is_none() {
                    return Ok(None);
                }
            }
            "clang-cl" => {
                if build_cl(member, corpus_root, &source_path, &out, "clang-cl")?.is_none() {
                    tracing::warn!(member = %member.name, "clang-cl unavailable; skipping member");
                    return Ok(None);
                }
            }
            other => bail!("unknown toolchain `{other}` for member {}", member.name),
        }

        anyhow::ensure!(out.is_file(), "build produced no output: {}", out.display());
        Ok(Some(out))
    }

    fn build_rustc(member: &Member, source: &Path, out: &Path) -> Result<()> {
        let mut cmd = Command::new("rustc");
        cmd.args(["-O", "--edition", "2021"]);
        if member.kind == MemberKind::Dll {
            cmd.args(["--crate-type", "cdylib"]);
        }
        for f in &member.flags {
            cmd.arg(f);
        }
        cmd.arg(source).arg("-o").arg(out);
        let status = cmd
            .status()
            .with_context(|| format!("spawning rustc for {}", member.name))?;
        anyhow::ensure!(status.success(), "rustc failed for {}", member.name);
        Ok(())
    }

    /// Returns `Ok(None)` when the compiler driver is unavailable.
    fn build_cl(
        member: &Member,
        corpus_root: &Path,
        source: &Path,
        out: &Path,
        driver: &str,
    ) -> Result<Option<()>> {
        let vcvars = match vcvars_path() {
            Some(p) => p,
            None => return Ok(None),
        };

        let mut parts: Vec<String> = vec![driver.to_string()];
        for f in &member.flags {
            parts.push(f.clone());
        }
        parts.push(quote(source));

        let mut link_args: Vec<String> = Vec::new();
        if member.kind == MemberKind::Dll {
            parts.push("/LD".to_string());
            parts.push(format!("/Fe:{}", out.display()));
        } else if member.link_shim {
            let shim = corpus_root.join("winshim").join("kamy_winshim.c");
            anyhow::ensure!(shim.is_file(), "winshim missing: {}", shim.display());
            parts.push(quote(&shim));
            parts.push(format!("/I{}", quote(&corpus_root.join("winshim"))));
            parts.push("/Fe:".to_string() + &out.display().to_string());
            link_args.push("/SUBSYSTEM:CONSOLE".to_string());
        } else {
            parts.push(format!("/Fe:{}", out.display()));
        }
        for lf in &member.link_flags {
            link_args.push(lf.clone());
        }
        if !link_args.is_empty() {
            parts.push("/link".to_string());
            parts.extend(link_args);
        }

        let build_cmd = parts.join(" ");
        let script = format!(
            "@echo off\r\ncall \"{}\" >nul\r\n{build_cmd}\r\n",
            vcvars.display()
        );
        let bat = std::env::temp_dir().join(format!(
            "kamy-build-{}-{}.bat",
            member.name,
            std::process::id()
        ));
        std::fs::write(&bat, script)
            .with_context(|| format!("writing build script for {}", member.name))?;
        let status = Command::new("cmd")
            .arg("/c")
            .arg(&bat)
            .current_dir(out.parent().unwrap_or_else(|| Path::new(".")))
            .status()
            .with_context(|| format!("spawning {driver} for {}", member.name));
        let _ = std::fs::remove_file(&bat);
        let status = status?;
        anyhow::ensure!(status.success(), "{driver} failed for {}", member.name);
        Ok(Some(()))
    }

    fn quote(p: &Path) -> String {
        format!("\"{}\"", p.display())
    }

    fn vcvars_path() -> Option<PathBuf> {
        let pf = std::env::var("ProgramFiles(x86)")
            .or_else(|_| std::env::var("ProgramFiles"))
            .ok()?;
        let vswhere = Path::new(&pf)
            .join("Microsoft Visual Studio")
            .join("Installer")
            .join("vswhere.exe");
        if !vswhere.is_file() {
            return None;
        }
        let out = Command::new(&vswhere)
            .args(["-latest", "-property", "installationPath"])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let install = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if install.is_empty() {
            return None;
        }
        let vcvars = Path::new(&install)
            .join("VC")
            .join("Auxiliary")
            .join("Build")
            .join("vcvars64.bat");
        vcvars.is_file().then_some(vcvars)
    }

    pub(super) fn rustc_version() -> Option<String> {
        let out = Command::new("rustc").arg("--version").output().ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    pub(super) fn cl_version() -> Option<String> {
        let vcvars = vcvars_path()?;
        let out = Command::new("cmd")
            .arg("/c")
            .arg(format!("\"{}\" && cl", vcvars.display()))
            .output()
            .ok()?;
        // cl prints its banner to stderr; grab the first non-empty line.
        let text = String::from_utf8_lossy(&out.stderr);
        text.lines()
            .map(str::trim)
            .find(|l| l.contains("Microsoft") && l.contains("C/C++"))
            .map(ToString::to_string)
    }
}
