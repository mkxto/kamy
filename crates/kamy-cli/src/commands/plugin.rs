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
    let ir = scratch.join("plugin.ll");
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let version = Process::new(&rustc)
        .arg("-vV")
        .output()
        .context("querying Rust LLVM version")?;
    ensure!(
        version.status.success(),
        "Rust compiler version query failed"
    );
    let version = String::from_utf8(version.stdout).context("Rust version is not UTF-8")?;
    let llvm_version = version
        .lines()
        .find_map(|l| l.strip_prefix("LLVM version: "))
        .context("rustc did not report its LLVM version")?;
    let host = version
        .lines()
        .find_map(|l| l.strip_prefix("host: "))
        .context("rustc did not report its host target")?;
    let sysroot = Process::new(&rustc)
        .args(["--print", "sysroot"])
        .output()
        .context("querying Rust sysroot")?;
    ensure!(sysroot.status.success(), "Rust sysroot query failed");
    let sysroot = String::from_utf8(sysroot.stdout).context("Rust sysroot is not UTF-8")?;
    let tools = std::env::var_os("KAMY_LLVM_TOOLS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(sysroot.trim())
                .join("lib")
                .join("rustlib")
                .join(host)
                .join("bin")
        });
    let llc = tools.join(if cfg!(windows) { "llc.exe" } else { "llc" });
    ensure!(
        llc.is_file(),
        "matching LLVM compiler {} is absent; install rustup component llvm-tools-preview or configure KAMY_LLVM_TOOLS_DIR with rustc-matched LLVM tools",
        llc.display()
    );
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
        .arg("--crate-type=staticlib")
        .arg(format!("--emit=llvm-ir={}", ir.display()))
        .args([
            "-C",
            "linker-plugin-lto=no",
            "-C",
            "embed-bitcode=yes",
            "-C",
            "lto=fat",
        ])
        .status()
        .context("running Cargo for Rust SDK plugin")?;
    ensure!(status.success(), "Rust plugin compilation failed: {status}");
    ensure!(
        ir.is_file(),
        "Cargo did not emit the Rust plugin post-LTO LLVM IR {}",
        ir.display()
    );
    kamy_pe::module::build_from_llvm_ir(&ir, output, entry, linker, &llc, llvm_version)
        .with_context(|| format!("packaging Rust plugin {}", output.display()))
}
