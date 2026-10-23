mod frame;
mod native;
mod pe;
mod probe;
mod report;

use anyhow::{Context, Result, ensure};
use kamy_run::{RunOptions, run_traced};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

struct Options {
    out: PathBuf,
    kamy: PathBuf,
    cargo: PathBuf,
    rustc: PathBuf,
    linker: PathBuf,
    llvm_tools: PathBuf,
    lib_dirs: String,
    scope: String,
}

impl Options {
    fn parse(arguments: &[String]) -> Result<Self> {
        let mut values = std::collections::BTreeMap::new();
        ensure!(
            arguments.len().is_multiple_of(2),
            "options MUST be --name value pairs"
        );
        for pair in arguments.chunks_exact(2) {
            ensure!(
                matches!(
                    pair[0].as_str(),
                    "--out"
                        | "--kamy"
                        | "--cargo"
                        | "--rustc"
                        | "--linker"
                        | "--llvm-tools"
                        | "--lib-dirs"
                        | "--scope"
                ),
                "unknown option {}",
                pair[0]
            );
            ensure!(
                values.insert(pair[0].clone(), pair[1].clone()).is_none(),
                "duplicate option {}",
                pair[0]
            );
        }
        let required = |name: &str| -> Result<PathBuf> {
            Ok(PathBuf::from(values.get(name).with_context(|| {
                format!("required option {name} is missing")
            })?))
        };
        let out = required("--out")?;
        std::fs::create_dir_all(&out)?;
        let result = Self {
            out: out.canonicalize()?,
            kamy: required("--kamy")?.canonicalize().context("resolving --kamy executable")?,
            cargo: required("--cargo")?,
            rustc: required("--rustc")?,
            linker: required("--linker")?,
            llvm_tools: required("--llvm-tools")?.canonicalize().context("resolving matching LLVM tools")?,
            lib_dirs: values.get("--lib-dirs").context("--lib-dirs MUST explicitly contain the Windows SDK, UCRT and MSVC library directories")?.clone(),
            scope: values.get("--scope").cloned().unwrap_or_else(|| "full".to_owned()),
        };
        ensure!(
            matches!(result.scope.as_str(), "full" | "preserved"),
            "--scope MUST be full or preserved"
        );
        ensure!(
            result.llvm_tools.join("llc.exe").is_file(),
            "--llvm-tools has no matching llc.exe"
        );
        let libraries: Vec<_> = std::env::split_paths(&result.lib_dirs).collect();
        ensure!(
            !libraries.is_empty()
                && libraries.iter().all(|path| path.is_dir())
                && libraries
                    .iter()
                    .any(|path| path.join("kernel32.lib").is_file()),
            "--lib-dirs contains invalid directories or no kernel32.lib"
        );
        Ok(result)
    }
}

fn source() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn capture(command: &mut Command) -> Result<Output> {
    println!("invoke={command:?}");
    let output = command
        .output()
        .with_context(|| format!("executing {command:?}"))?;
    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    Ok(output)
}

fn invoke(command: &mut Command) -> Result<Output> {
    let output = capture(command)?;
    ensure!(
        output.status.success(),
        "command failed ({}): {command:?}",
        output.status
    );
    Ok(output)
}

fn build(options: &Options) -> Result<()> {
    let build = options.out.join("host-build");
    let rustflags = format!(
        "-Clinker={}\x1f-Clink-arg=/base:0x7ffe0000\x1f-Clink-arg=/dynamicbase\x1f-Clink-arg=/fixed:no\x1f-Clink-arg=/export:SDK_STATE\x1f-Clink-arg=/export:HOST_BSS\x1f-Clink-arg=/timestamp:0",
        options.linker.display()
    );
    invoke(
        Command::new(&options.cargo)
            .args([
                "build",
                "--release",
                "--target",
                "x86_64-pc-windows-msvc",
                "--bin",
                "sdk-host-exe",
                "--manifest-path",
            ])
            .arg(source().join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&build)
            .env("LIB", &options.lib_dirs)
            .env("RUSTC", &options.rustc)
            .env("CARGO_ENCODED_RUSTFLAGS", rustflags),
    )?;
    std::fs::copy(
        build.join("x86_64-pc-windows-msvc/release/sdk-host-exe.exe"),
        options.out.join("host-original.exe"),
    )?;
    let object = options.out.join("host-original.obj");
    invoke(
        Command::new(&options.rustc)
            .args([
                "--edition",
                "2024",
                "--target",
                "x86_64-pc-windows-msvc",
                "--crate-type",
                "lib",
                "-C",
                "opt-level=1",
                "-C",
                "panic=abort",
            ])
            .arg(format!("--emit=obj={}", object.display()))
            .arg(source().join("hosts/dll.rs")),
    )?;
    invoke(
        Command::new(&options.linker)
            .args([
                "/dll",
                "/nodefaultlib",
                "/machine:x64",
                "/entry:DllMain",
                "/base:0x180000000",
                "/dynamicbase",
                "/fixed:no",
                "/opt:noref",
                "/opt:noicf",
                "/timestamp:0",
                "/export:SDK_STATE,DATA",
                "/export:HOST_BSS,DATA",
                "/export:HOST_READ_ONLY,DATA",
                "/export:HOST_INTERIOR,DATA",
                "/export:DllMain",
            ])
            .arg(format!(
                "/out:{}",
                options.out.join("host-original.dll").display()
            ))
            .arg(object)
            .arg("kernel32.lib")
            .env("LIB", &options.lib_dirs),
    )?;
    for extension in ["exe", "dll"] {
        let host = pe::Pe::read(&options.out.join(format!("host-original.{extension}")))?;
        let exports = host.exports()?;
        ensure!(
            exports.contains_key("SDK_STATE") && exports.contains_key("HOST_BSS"),
            "built host lacks observable state exports"
        );
        println!(
            "host={extension} image_base={:#x} state_rva={:#x}",
            host.image_base, exports["SDK_STATE"]
        );
    }
    frame::build(options)?;
    Ok(())
}

fn members(variant: &str) -> Vec<&'static str> {
    match variant {
        "ordered" => vec!["first", "second"],
        "abi" => vec!["first", "second", "abi"],
        "bounds" => vec!["first", "second", "bounds"],
        "fastfail" => vec!["first", "fastfail", "second"],
        "pressure" => vec!["pressure", "second"],
        _ => unreachable!(),
    }
}

fn produce(options: &Options) -> Result<()> {
    let mut failures = Vec::new();
    for host in ["exe", "dll"] {
        let pe = pe::Pe::read(&options.out.join(format!("host-original.{host}")))?;
        let trace_rva = *pe
            .exports()?
            .get("SDK_STATE")
            .context("host lacks SDK_STATE")?;
        for name in ["first", "second", "abi", "bounds", "fastfail", "pressure"] {
            if name == "pressure" && host == "dll" {
                continue;
            }
            let table_bytes = if name == "pressure" {
                24
            } else if host == "exe" {
                32
            } else {
                24
            };
            let result = invoke(
                Command::new(&options.kamy)
                    .args(["plugin", "build", "--manifest-path"])
                    .arg(source().join(format!("plugins/{name}/Cargo.toml")))
                    .arg("--output")
                    .arg(options.out.join(format!("{host}-{name}.dll")))
                    .arg("--linker")
                    .arg(&options.linker)
                    .env("CARGO", &options.cargo)
                    .env("RUSTC", &options.rustc)
                    .env("KAMY_LLVM_TOOLS_DIR", &options.llvm_tools)
                    .env("SDK_TRACE_RVA", trace_rva.to_string())
                    .env("SDK_TABLE_BYTES", table_bytes.to_string()),
            )
            .and_then(|_| {
                if name == "abi" {
                    report::inspect_scalar_producer(&options.out.join(format!("{host}-abi.dll")))?;
                }
                Ok(())
            });
            if let Err(error) = result {
                failures.push(format!("{host}-{name}: {error:#}"));
            }
        }
        for variant in ["ordered", "abi", "bounds", "fastfail", "pressure"] {
            if variant == "pressure" && host == "dll" {
                continue;
            }
            for mode in ["inline", "init-table"] {
                if variant == "pressure" && mode == "inline" {
                    continue;
                }
                let mut profile = format!(
                    "version: '1'\nmodule_settings:\n  injection:\n    enabled: true\n    mode: {mode}\n    plugins:\n"
                );
                for member in members(variant) {
                    profile.push_str(&format!(
                        "      - name: {member}\n        path: {host}-{member}.dll\n"
                    ));
                }
                if matches!(variant, "ordered" | "pressure") {
                    let ordered = include_str!(
                        "../../../crates/kamy-cli/tests/fixtures/profiles/ordered-mba.yml"
                    );
                    let passes = ordered
                        .split_once("profiles:\n")
                        .context("ordered fixture has no profiles")?
                        .1;
                    profile = profile.replacen(
                        "  injection:\n",
                        "  custom_section_name: {enabled: true, value: '.cache'}\n  injection:\n",
                        1,
                    );
                    profile.push_str("profiles:\n");
                    profile.push_str(passes);
                    profile.push_str(&format!(
                        "  symbols:\n  - !Pattern '{}::*'\n  - !Pattern 'second::*'\n",
                        if variant == "pressure" {
                            "pressure"
                        } else {
                            "first"
                        }
                    ));
                } else {
                    profile.push_str("profiles:\n  - name: identity-contract\n    passes:\n      - type: MixedBooleanArithmetic\n        iterations: 1\n        probability: 100\n        semantics: {add: true, sub: true, xor: true}\n");
                }
                std::fs::write(
                    options.out.join(format!("{host}-{variant}-{mode}.yml")),
                    profile,
                )?;
            }
        }
    }
    ensure!(
        failures.is_empty(),
        "producer failures (mandatory cases are not skipped):\n{}",
        failures.join("\n")
    );
    frame::produce(options)?;
    Ok(())
}

fn run_target(
    executable: &Path,
    arguments: Vec<String>,
    environment: Vec<(String, String)>,
    fastfail: bool,
) -> Result<()> {
    let pressure_witness = environment
        .iter()
        .any(|(name, value)| name == "SDK_VARIANT" && value == "pressure");
    let outcome = run_traced(&RunOptions {
        exe: executable.to_owned(),
        args: arguments,
        env: environment,
        timeout: Duration::from_secs(30),
        ..Default::default()
    })
    .with_context(|| {
        format!(
            "running actual runtime target {} through kamy-run",
            executable.display()
        )
    })?;
    print!("{}", String::from_utf8_lossy(&outcome.stdout));
    eprint!("{}", String::from_utf8_lossy(&outcome.stderr));
    ensure!(!outcome.timed_out, "runtime target timed out");
    if fastfail {
        ensure!(
            outcome
                .exit_code
                .is_none_or(|value| value as u32 == 0xc000_0409)
                && outcome.fault.is_some_and(|fault| fault.code == 0xc000_0409),
            "nonzero callback did not produce native fast-fail: exit={:?}, fault={:?}",
            outcome.exit_code,
            outcome.fault
        );
        ensure!(
            outcome.stdout.is_empty(),
            "host entry ran despite nonzero callback"
        );
        println!("fastfail=0xc0000409");
    } else {
        ensure!(
            outcome.exit_code == Some(0) && outcome.fault.is_none(),
            "runtime oracle failed: exit={:?}, fault={:?}",
            outcome.exit_code,
            outcome.fault
        );
        ensure!(
            !outcome.stdout.is_empty(),
            "runtime target produced no behavior oracle"
        );
        if pressure_witness {
            ensure!(
                String::from_utf8_lossy(&outcome.stdout)
                    .lines()
                    .any(|line| line.starts_with("trace=12 ") && line.ends_with("aslr=1 host=exe")),
                "combined bounds/counter witness did not execute its host-visible oracle under ASLR"
            );
        }
    }
    Ok(())
}

fn execute(
    _options: &Options,
    output: &Path,
    host: &str,
    variant: &str,
    ranges: &str,
) -> Result<()> {
    if host == "exe" {
        let mut environment = vec![("SDK_VARIANT".to_owned(), variant.to_owned())];
        if !ranges.is_empty() {
            environment.push(("SDK_UNWIND_PROBES".to_owned(), ranges.to_owned()));
        }
        run_target(output, Vec::new(), environment, variant == "fastfail")
    } else {
        run_target(
            &std::env::current_exe()?,
            vec![
                "probe-dll".to_owned(),
                output.to_string_lossy().into_owned(),
                variant.to_owned(),
                ranges.to_owned(),
            ],
            Vec::new(),
            variant == "fastfail",
        )
    }
}

fn protect(options: &Options, host: &str, variant: &str, mode: &str, identity: bool) -> Result<()> {
    let original = options.out.join(format!("host-original.{host}"));
    let stem = format!("{host}-{variant}-{mode}");
    let directory = if matches!(variant, "ordered" | "pressure") {
        options.out.join(if identity { "identity" } else { "mba" })
    } else {
        options.out.clone()
    };
    std::fs::create_dir_all(&directory)?;
    let output = directory.join(format!("{stem}.{host}"));
    let map = directory.join(format!("{stem}.csv"));
    let link_report = directory.join(format!("{stem}.json"));
    let mut command = Command::new(&options.kamy);
    command
        .arg("protect")
        .arg(&original)
        .arg("--output")
        .arg(&output)
        .arg("--debug-map")
        .arg(&map)
        .arg("--link-report")
        .arg(&link_report);
    if identity {
        command.arg("--ssa-identity");
    }
    let module_names = if variant == "baseline" {
        Vec::new()
    } else {
        command
            .arg("--profile")
            .arg(options.out.join(format!("{stem}.yml")));
        members(variant)
    };
    let result = capture(&mut command).with_context(|| format!("protecting {stem}"))?;
    let diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    ensure!(
        result.status.success(),
        "protecting {stem} failed ({}); mandatory authored functions MUST lower without a verbatim fallback:\n{diagnostic}",
        result.status
    );
    let abi_module = (variant == "abi").then(|| options.out.join(format!("{host}-abi.dll")));
    let inspection = report::inspect(
        &original,
        &output,
        &map,
        &link_report,
        &module_names,
        identity,
        abi_module.as_deref(),
    )?;
    if variant == "pressure" {
        inspect_transform_report(&link_report, identity, &["pressure", "second"])?;
    }
    if variant == "ordered" {
        inspect_transform_report(&link_report, identity, &["first", "second"])?;
        let original_pe = pe::Pe::read(&original)?;
        let output_pe = pe::Pe::read(&output)?;
        ensure!(
            output_pe.sections.len() > original_pe.sections.len(),
            "ordered profile added no sections"
        );
        ensure!(
            output_pe.sections[original_pe.sections.len()..]
                .iter()
                .all(|section| section.name == ".cache"),
            "profile section naming was not honored"
        );
    }
    println!("bss_virtual_ranges={}", inspection.bss_rvas.len());
    execute(
        options,
        &output,
        host,
        variant,
        if variant == "baseline" || variant == "fastfail" {
            ""
        } else {
            &inspection.unwind_ranges
        },
    )?;
    Ok(())
}

fn inspect_transform_report(path: &Path, identity: bool, modules: &[&str; 2]) -> Result<()> {
    let report: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
    let functions = report["functions"]
        .as_array()
        .context("report has no functions")?;
    let mut transformed = [0usize; 2];
    let mut selected = [0usize; 2];
    for function in functions {
        let changed = function["transformed"]
            .as_bool()
            .context("missing transformed")?;
        let lowered = function["lowered"].as_bool().context("missing lowered")?;
        let is_selected = function["selected"].as_bool().context("missing selected")?;
        let intensity = function["intensity"]
            .as_f64()
            .context("missing intensity")?;
        ensure!(
            (0.0..=1.0).contains(&intensity),
            "invalid actual intensity {intensity}"
        );
        ensure!(
            !changed || (lowered && is_selected && !identity),
            "report falsely claims a semantic transform: {function}"
        );
        let module = function["symbol"]["source_module"].as_str();
        if let Some(index) = modules.iter().position(|name| Some(*name) == module) {
            if is_selected && lowered {
                report::inspect_allocation(function, module == Some("pressure"))?;
                ensure!(
                    if identity {
                        intensity == 0.0
                    } else {
                        intensity == 1.0
                    },
                    "callback lowering reduced or ignored the requested MBA intensity: {function}"
                );
                selected[index] += 1;
                transformed[index] += usize::from(changed);
            }
        } else {
            ensure!(
                !is_selected && !changed,
                "qualified selectors selected an unrelated function: {function}"
            );
        }
    }
    ensure!(
        selected.iter().all(|count| *count > 0),
        "both qualified callback modules MUST actually lower: {modules:?}"
    );
    if !identity {
        ensure!(
            transformed.iter().all(|count| *count > 0),
            "configured MBA did not actually transform both callback modules: {modules:?}"
        );
    }
    println!(
        "transform-report modules={modules:?} identity={identity} lowered={selected:?} transformed={transformed:?}"
    );
    Ok(())
}

fn configuration_acceptance(options: &Options) -> Result<()> {
    let directory = options.out.join("configuration");
    std::fs::create_dir_all(&directory)?;
    let unsupported =
        include_str!("../../../crates/kamy-cli/tests/fixtures/profiles/unsupported-references.yml");
    let disabled =
        include_str!("../../../crates/kamy-cli/tests/fixtures/profiles/disabled-injection.yml");
    let mut failures = Vec::new();
    let cases: [(&str, &str, &[&str], &[&str]); 5] = [
        (
            "unsupported-pass",
            unsupported,
            &[],
            &[
                "profiles[0]",
                "unsupported-reference-witness",
                "ObscureReferences",
            ],
        ),
        (
            "unsupported-setting",
            "version: '1'\nmodule_settings:\n  import_protection: true\n",
            &[],
            &["module_settings.import_protection"],
        ),
        (
            "profile-selector-conflict",
            disabled,
            &["--only-rva", "0x1000"],
            &["conflict with --profile"],
        ),
        (
            "selector-conflict",
            disabled,
            &["--only-rva", "0x1000", "--reject-rva", "0x1000"],
            &["mutually exclusive"],
        ),
        (
            "unsupported-pass-identity",
            unsupported,
            &["--ssa-identity"],
            &["profiles[0]", "ObscureReferences"],
        ),
    ];
    for (name, yaml, flags, expected) in cases {
        let result = (|| -> Result<()> {
            let profile = directory.join(format!("{name}.yml"));
            let output = directory.join(format!("{name}.exe"));
            ensure!(
                !output.exists(),
                "rejection target already exists: {}",
                output.display()
            );
            std::fs::write(&profile, yaml)?;
            let result = capture(
                Command::new(&options.kamy)
                    .arg("protect")
                    .arg(options.out.join("host-original.exe"))
                    .arg("--profile")
                    .arg(&profile)
                    .arg("--output")
                    .arg(&output)
                    .args(flags),
            )?;
            let diagnostic = format!(
                "{}{}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
            ensure!(!result.status.success(), "{name} falsely succeeded");
            ensure!(!output.exists(), "{name} wrote a falsely successful output");
            ensure!(
                expected.iter().all(|text| diagnostic.contains(text)),
                "{name} lacks contextual rejection: {diagnostic}"
            );
            println!("PASS configuration-{name}");
            Ok(())
        })();
        if let Err(error) = result {
            failures.push(format!("{name}: {error:#}"));
        }
    }
    let disabled_profile = directory.join("disabled.yml");
    std::fs::write(&disabled_profile, disabled)?;
    ensure!(
        !directory.join("does-not-exist.dll").exists(),
        "disabled injection witness path MUST be absent"
    );
    for host in ["exe", "dll"] {
        let result = (|| -> Result<()> {
            let output = directory.join(format!("disabled.{host}"));
            let report = directory.join(format!("disabled-{host}.json"));
            invoke(
                Command::new(&options.kamy)
                    .arg("protect")
                    .arg(options.out.join(format!("host-original.{host}")))
                    .arg("--profile")
                    .arg(&disabled_profile)
                    .arg("--output")
                    .arg(&output)
                    .arg("--link-report")
                    .arg(&report),
            )?;
            let value: serde_json::Value = serde_json::from_slice(&std::fs::read(report)?)?;
            let functions = value["functions"]
                .as_array()
                .context("disabled report lacks functions")?;
            ensure!(
                functions
                    .iter()
                    .all(|function| function["transformed"] == false
                        && function["symbol"]["origin"] != "authored"),
                "disabled plugin was loaded or empty passes transformed code"
            );
            execute(options, &output, host, "baseline", "")?;
            println!("PASS configuration-disabled-missing-{host}");
            Ok(())
        })();
        if let Err(error) = result {
            failures.push(format!("disabled-{host}: {error:#}"));
        }
    }
    ensure!(
        failures.is_empty(),
        "configuration failures:\n{}",
        failures.join("\n")
    );
    Ok(())
}

fn run(options: &Options) -> Result<()> {
    let mut failures = Vec::new();
    for host in ["exe", "dll"] {
        let original = options.out.join(format!("host-original.{host}"));
        if let Err(error) = execute(options, &original, host, "baseline", "") {
            failures.push(format!("original-{host}: {error:#}"));
        }
        if let Err(error) = protect(options, host, "baseline", "identity", true) {
            failures.push(format!("host-only-{host}: {error:#}"));
        }
        for variant in ["ordered", "abi", "bounds", "fastfail"] {
            for mode in ["inline", "init-table"] {
                match protect(options, host, variant, mode, true) {
                    Ok(()) => println!("PASS {host}-{variant}-{mode}"),
                    Err(error) => {
                        eprintln!("FAIL {host}-{variant}-{mode}: {error:#}");
                        failures.push(format!("{host}-{variant}-{mode}: {error:#}"));
                    }
                }
            }
        }
    }
    if options.scope == "full" {
        for host in ["exe", "dll"] {
            for mode in ["inline", "init-table"] {
                if let Err(error) = protect(options, host, "ordered", mode, false) {
                    failures.push(format!("mba-{host}-ordered-{mode}: {error:#}"));
                }
            }
        }
        if let Err(error) = configuration_acceptance(options) {
            failures.push(format!("configuration: {error:#}"));
        }
        if let Err(error) = frame::run(options) {
            failures.push(format!("memory-frame-runtime: {error:#}"));
        }
        for identity in [true, false] {
            match protect(options, "exe", "pressure", "init-table", identity) {
                Ok(()) => println!(
                    "PASS combined-pressure-witness identity={identity} trace=12 bounds=24"
                ),
                Err(error) => {
                    eprintln!("FAIL combined-pressure-witness identity={identity}: {error:#}");
                    failures.push(format!(
                        "combined-pressure-witness identity={identity}: {error:#}"
                    ));
                }
            }
        }
    } else {
        println!("combined-pressure-witness=NOT_RUN explicit_scope=preserved");
    }
    ensure!(
        failures.is_empty(),
        "acceptance failures:\n{}",
        failures.join("\n")
    );
    println!("sdk-rebuild={} PASS", options.scope);
    Ok(())
}

fn main() -> Result<()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let (phase, rest) = arguments.split_first().context("usage: sdk-rebuild <build|produce|run|all> --out PATH --kamy EXE --cargo CARGO --rustc RUSTC --linker LLD_LINK --llvm-tools DIRECTORY --lib-dirs SEMICOLON_PATHS [--scope full|preserved]")?;
    if phase == "probe-dll" {
        return probe::dispatch(rest);
    }
    if phase == "probe-frame" {
        return frame::probe(rest);
    }
    ensure!(
        matches!(phase.as_str(), "build" | "produce" | "run" | "all"),
        "unknown phase {phase}"
    );
    let options = Options::parse(rest)?;
    if phase == "build" || phase == "all" {
        build(&options)?;
    }
    if phase == "produce" || phase == "all" {
        produce(&options)?;
    }
    if phase == "run" || phase == "all" {
        run(&options)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions, FlowControl, OpKind};
    use kamy_core::{LinkField, SymbolicExpression};
    use kamy_pe::module::{AuthoredModule, CodeSymbol};

    fn real_call_contract<'a>(
        module: &'a AuthoredModule,
        caller: &CodeSymbol,
        instruction: &iced_x86::Instruction,
    ) -> Result<&'a CodeSymbol> {
        let field = u32::try_from(instruction.next_ip() - 4)? - caller.start.get();
        let mut references = module.references.iter().filter(|reference| {
            reference.source == caller.symbol
                && reference.offset == field
                && matches!(reference.field, LinkField::Relative32 { bias: 0 })
        });
        let reference = references
            .next()
            .context("real call lacks its COFF reference")?;
        ensure!(references.next().is_none(), "ambiguous real call reference");
        let mut expression = reference.expression.clone();
        for _ in 0..=module.bindings.len() {
            let SymbolicExpression::Symbol { symbol, addend } = expression else {
                anyhow::bail!("real call target is not a single authored symbol");
            };
            if addend == 0
                && let Some(function) = module.code.iter().find(|code| code.symbol == symbol)
            {
                ensure!(
                    u64::from(function.start.get()) == instruction.near_branch64(),
                    "resolved call contract differs from its encoded target"
                );
                return Ok(function);
            }
            expression = module
                .bindings
                .get(&symbol)
                .context("real call target lacks an accepted authored contract")?
                .clone()
                .with_addend(addend)
                .context("real call alias addend overflows")?;
        }
        anyhow::bail!("cyclic real call target bindings")
    }

    #[test]
    #[ignore = "requires explicit SDK_ABI_* CLI/compiler paths and matching LLVM 22.1.2 tools"]
    fn real_rust_llvm_call_contracts_preserve_win64_nonvolatiles() -> Result<()> {
        use kamy_core::ir::{AbiClass, AbiPassing, win64_volatiles};
        use std::path::PathBuf;
        use std::process::Command;

        let parameter = |name| -> Result<PathBuf> {
            Ok(PathBuf::from(std::env::var_os(name).with_context(
                || {
                    format!(
                        "{name} MUST explicitly select the real producer tool or evidence directory"
                    )
                },
            )?))
        };
        let kamy = parameter("SDK_ABI_KAMY")?;
        let cargo = parameter("SDK_ABI_CARGO")?;
        let rustc = parameter("SDK_ABI_RUSTC")?;
        let linker = parameter("SDK_ABI_LINKER")?;
        let llvm = parameter("KAMY_LLVM_TOOLS_DIR")?;
        let out = parameter("SDK_ABI_OUT")?;
        std::fs::create_dir_all(&out)?;
        let artifact = out.join("real-rust-call-contracts.dll");
        let rust_version = crate::invoke(Command::new(&rustc).arg("-vV"))?;
        let llvm_version = crate::invoke(
            Command::new(llvm.join(if cfg!(windows) { "llc.exe" } else { "llc" })).arg("--version"),
        )?;
        crate::invoke(
            Command::new(&kamy)
                .args(["plugin", "build", "--manifest-path"])
                .arg(crate::source().join("plugins/abi/Cargo.toml"))
                .arg("--output")
                .arg(&artifact)
                .arg("--linker")
                .arg(&linker)
                .env("CARGO", &cargo)
                .env("RUSTC", &rustc)
                .env("KAMY_LLVM_TOOLS_DIR", &llvm)
                .env("SDK_TRACE_RVA", "4096")
                .env("SDK_TABLE_BYTES", "24"),
        )?;
        let mut evidence = format!(
            "artifact={}\nrustc={}\nllc={}\n",
            artifact.display(),
            String::from_utf8(rust_version.stdout)?,
            String::from_utf8(llvm_version.stdout)?,
        );
        std::fs::write(out.join("call-contracts.txt"), &evidence)?;
        let pe = crate::pe::Pe::read(&artifact)?;
        let metadata = pe
            .sections
            .iter()
            .find(|section| section.name == ".kmod")
            .context("real producer omitted its compiler evidence")?;
        std::fs::write(
            out.join("compiler-metadata.bin"),
            pe.slice(metadata.rva, metadata.virtual_size as usize)?,
        )?;
        // Save raw compiler evidence before the normal public parser can reject it.
        let module = AuthoredModule::parse(&pe.bytes, "abi")?;
        let mut calls = Vec::new();
        let mut invalid = Vec::new();
        for function in &module.code {
            let signature = &function.signature;
            evidence.push_str(&format!(
                "symbol={} begin={:#x} end={:#x} abi={signature:?}\n",
                function.name,
                function.start.get(),
                function.end.get()
            ));
            let decoder = Decoder::with_ip(
                64,
                pe.slice(
                    function.start.get(),
                    (function.end.get() - function.start.get()) as usize,
                )?,
                u64::from(function.start.get()),
                DecoderOptions::NONE,
            );
            for instruction in decoder {
                if instruction.is_invalid()
                    || instruction.flow_control() == FlowControl::IndirectCall
                {
                    invalid.push(format!(
                        "invalid or unresolved producer instruction at {:#x}: {instruction:?}",
                        instruction.ip()
                    ));
                }
                if instruction.flow_control() == FlowControl::Call
                    && instruction.op0_kind() == OpKind::NearBranch64
                {
                    let contract = real_call_contract(&module, function, &instruction);
                    evidence.push_str(&format!(
                        "caller={:#x} call={:#x} target={:#x} resolved_contract={contract:?}\n",
                        function.start.get(),
                        instruction.ip(),
                        instruction.near_branch64(),
                    ));
                    calls.push((function.start.get(), instruction.ip(), contract));
                }
            }
        }
        for error in &invalid {
            evidence.push_str(&format!("decode_error={error}\n"));
        }
        // AuthoredModule has per-target contracts, derived from consensus native
        // CALL masks, not separate per-PC signatures. Resolve every actual CALL
        // through its accepted COFF reference/bindings, as the authored lifter does.
        std::fs::write(out.join("call-contracts.txt"), &evidence)?;
        ensure!(invalid.is_empty(), "{}", invalid.join("\n"));
        let volatile = win64_volatiles();
        let preserves_nonvolatiles = |signature: &kamy_core::ir::FnSignature| {
            signature.clobbers.iter().all(|reg| volatile.contains(reg))
                && signature.returns.iter().all(|value| {
                    value
                        .register_location()
                        .is_some_and(|reg| volatile.contains(&reg))
                })
        };
        for function in &module.code {
            ensure!(
                preserves_nonvolatiles(&function.signature),
                "real compiler defines a Win64 nonvolatile in {}: {:?}",
                function.name,
                function.signature
            );
        }
        for (caller, pc, contract) in &calls {
            let target = contract
                .as_ref()
                .map_err(|error| anyhow::anyhow!("{error:#}"))?;
            ensure!(
                preserves_nonvolatiles(&target.signature),
                "accepted real call defines a Win64 nonvolatile: caller={caller:#x} pc={pc:#x} target={} abi={:?}",
                target.name,
                target.signature
            );
        }
        let mut reachable = std::collections::BTreeSet::from([module.entry.get()]);
        loop {
            let before = reachable.len();
            for (caller, _, contract) in &calls {
                if reachable.contains(caller) {
                    let target = contract
                        .as_ref()
                        .map_err(|error| anyhow::anyhow!("{error:#}"))?;
                    reachable.insert(target.start.get());
                }
            }
            if before == reachable.len() {
                break;
            }
        }
        crate::report::inspect_scalar_producer(&artifact)?;
        for helper in [
            "integer",
            "sdk_rebuild_scalar_f64",
            "mixed",
            "aggregate",
            "sdk_rebuild_hidden_aggregate",
        ] {
            let mut matching = module.code.iter().filter(|function| {
                if helper == "sdk_rebuild_hidden_aggregate" {
                    function.name == helper
                } else {
                    function.name.contains(helper)
                        && function.name != "sdk_rebuild_hidden_aggregate"
                }
            });
            let function = matching
                .next()
                .with_context(|| format!("producer lost {helper}"))?;
            ensure!(matching.next().is_none(), "producer duplicated {helper}");
            ensure!(
                reachable.contains(&function.start.get())
                    && calls.iter().any(|(caller, _, contract)| {
                        reachable.contains(caller)
                            && *caller != function.start.get()
                            && contract
                                .as_ref()
                                .is_ok_and(|target| target.symbol == function.symbol)
                    }),
                "callback has no reachable real cross-function call to {helper}"
            );
            if helper == "integer" {
                ensure!(
                    function.signature.returns.iter().any(|value| {
                        value.class == AbiClass::Integer
                            && value.bits == 64
                            && value.passing == AbiPassing::Direct
                    }),
                    "real integer helper did not exercise a direct integer result"
                );
            }
            if helper == "mixed" {
                ensure!(
                    function
                        .signature
                        .returns
                        .iter()
                        .any(|value| value.class == AbiClass::Integer)
                        && function
                            .signature
                            .returns
                            .iter()
                            .any(|value| value.class == AbiClass::Float)
                        && function
                            .signature
                            .returns
                            .iter()
                            .all(|value| value.passing == AbiPassing::Direct),
                    "real mixed tuple did not exercise integer/float result pieces"
                );
            }
            if helper == "sdk_rebuild_hidden_aggregate" {
                ensure!(
                    function.signature.args.iter().any(|value| {
                        value.class == AbiClass::Pointer
                            && value.bits == 64
                            && matches!(value.passing, AbiPassing::Sret { size: 24, align: 8 })
                    }) && function.signature.returns.iter().any(|value| {
                        value.class == AbiClass::Pointer
                            && value.bits == 64
                            && value.passing == AbiPassing::Direct
                    }),
                    "real extern C aggregate lacks the hidden 24-byte result pointer input/return: {:?}",
                    function.signature
                );
            }
        }
        println!("{evidence}real_rust_call_contracts=PASS");
        Ok(())
    }
}
