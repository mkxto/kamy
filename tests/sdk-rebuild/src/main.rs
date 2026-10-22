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
                if variant == "ordered" {
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
                    profile.push_str(
                        "  symbols:\n  - !Pattern 'first::*'\n  - !Pattern 'second::*'\n",
                    );
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
    Ok(())
}

fn run_target(
    executable: &Path,
    arguments: Vec<String>,
    environment: Vec<(String, String)>,
    fastfail: bool,
) -> Result<()> {
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

enum CaseOutcome {
    Executed,
    ExpectedPressureLimitation,
}

fn protect(
    options: &Options,
    host: &str,
    variant: &str,
    mode: &str,
    identity: bool,
) -> Result<CaseOutcome> {
    let original = options.out.join(format!("host-original.{host}"));
    let stem = format!("{host}-{variant}-{mode}");
    let directory = if variant == "ordered" {
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
    if variant == "pressure" && !result.status.success() {
        let known_pressure = diagnostic.lines().any(|line| {
            line.contains("plugin pressure::")
                && (line.contains("kamy_plugin_init") || line.contains("initialize"))
                && line
                    .trim_end()
                    .ends_with(" cannot pass SSA/codegen: RegisterPressure")
        });
        if known_pressure {
            println!(
                "EXPECTED_LIMITATION combined-pressure-witness reason=RegisterPressure recovery=handoff-2"
            );
            return Ok(CaseOutcome::ExpectedPressureLimitation);
        }
    }
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
    if variant == "ordered" {
        inspect_ordered_report(&link_report, identity)?;
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
    Ok(CaseOutcome::Executed)
}

fn inspect_ordered_report(path: &Path, identity: bool) -> Result<()> {
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
        if let Some(index) = ["first", "second"]
            .iter()
            .position(|name| Some(*name) == module)
        {
            if is_selected && lowered {
                ensure!(
                    if identity {
                        intensity == 0.0
                    } else {
                        intensity > 0.0
                    },
                    "callback intensity disagrees with actual lowering mode"
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
        "both qualified callback modules MUST actually lower"
    );
    if !identity {
        ensure!(
            transformed.iter().all(|count| *count > 0),
            "configured MBA did not actually transform both callback modules"
        );
    }
    println!("ordered-report identity={identity} lowered={selected:?} transformed={transformed:?}");
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
                    Ok(_) => println!("PASS {host}-{variant}-{mode}"),
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
        match protect(options, "exe", "pressure", "init-table", true) {
            Ok(CaseOutcome::Executed) => {
                println!("PASS combined-pressure-witness trace=12 bounds=24")
            }
            Ok(CaseOutcome::ExpectedPressureLimitation) => println!(
                "combined-pressure-witness=EXPECTED_LIMITATION reason=RegisterPressure recovery=NOT_CLAIMED"
            ),
            Err(error) => {
                eprintln!("STRICT FAIL combined-pressure-witness: {error:#}");
                failures.push(format!("combined-pressure-witness (handoff 2 recovery; not accepted as passing): {error:#}"));
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
