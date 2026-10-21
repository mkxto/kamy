use std::path::{Path, PathBuf};
use std::process::Command as Process;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, ensure};
use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Build a Rust Cargo library into a statically linkable SDK module.
    Build {
        #[arg(long)]
        manifest_path: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long, default_value = "kamy_plugin_init")]
        entry: String,
        #[arg(long, default_value = "lld-link")]
        linker: PathBuf,
    },
}

pub(crate) fn dispatch(command: Command) -> anyhow::Result<()> {
    let Command::Build {
        manifest_path,
        output,
        entry,
        linker,
    } = command;
    let manifest = manifest_path
        .canonicalize()
        .with_context(|| format!("resolving Rust plugin manifest {}", manifest_path.display()))?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("reading plugin build timestamp")?
        .as_nanos();
    let scratch =
        std::env::temp_dir().join(format!("kamy-rust-plugin-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&scratch).context("creating Rust plugin build directory")?;
    let result = build(&manifest, &output, &entry, &linker, &scratch);
    let cleanup = std::fs::remove_dir_all(&scratch).context("removing Rust plugin build directory");
    result.and(cleanup)?;
    println!("plugin built: {}", output.display());
    Ok(())
}

fn build(
    manifest: &Path,
    output: &Path,
    entry: &str,
    linker: &Path,
    scratch: &Path,
) -> anyhow::Result<()> {
    let object = scratch.join("plugin.obj");
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = Process::new(cargo)
        .args([
            "rustc",
            "--lib",
            "--release",
            "--target",
            "x86_64-pc-windows-msvc",
        ])
        .arg("--manifest-path")
        .arg(manifest)
        .arg("--target-dir")
        .arg(scratch.join("target"))
        .args([
            "--config",
            "profile.release.lto=\"fat\"",
            "--config",
            "profile.release.codegen-units=1",
            "--config",
            "profile.release.panic=\"abort\"",
            "--",
        ])
        .arg(format!("--emit=obj={}", object.display()))
        .args(["-C", "linker-plugin-lto=no"])
        .status()
        .context("running Cargo for Rust SDK plugin")?;
    ensure!(status.success(), "Rust plugin compilation failed: {status}");
    ensure!(
        object.is_file(),
        "Cargo did not emit the Rust plugin native object {}",
        object.display()
    );
    kamy_pe::module::build(&[object], output, entry, linker)
        .with_context(|| format!("packaging Rust plugin {}", output.display()))
}
