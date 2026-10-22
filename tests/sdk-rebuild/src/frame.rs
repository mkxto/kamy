use crate::{Options, capture, invoke, native, pe::Pe, run_target, source};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::ffi::c_void;
use std::path::Path;
use std::process::Command;

const EXPORTS: &[&str] = &[
    "DllMain",
    "frame_mix6",
    "frame_touch",
    "frame_stack6",
    "frame_pinned",
    "frame_mixed",
    "frame_recursive",
    "frame_large",
    "frame_saves",
];

pub fn build(options: &Options) -> Result<()> {
    let probe_library = std::env::split_paths(&options.lib_dirs)
        .map(|directory| directory.join("libcmt.lib"))
        .find(|path| path.is_file())
        .context("--lib-dirs MUST include the MSVC libcmt.lib stack-probe provider")?;
    let mut command = Command::new(&options.rustc);
    command.args([
        "--edition",
        "2024",
        "--target",
        "x86_64-pc-windows-msvc",
        "--crate-type",
        "cdylib",
        "-C",
        "opt-level=1",
        "-C",
        "panic=abort",
    ]);
    command.arg(format!("-Clinker={}", options.linker.display()));
    command.arg(format!("-Clink-arg={}", probe_library.display()));
    for argument in [
        "/entry:DllMain",
        "/nodefaultlib",
        "/base:0x180000000",
        "/dynamicbase",
        "/fixed:no",
        "/opt:noref",
        "/opt:noicf",
        "/timestamp:0",
        "/export:__chkstk",
    ] {
        command.arg(format!("-Clink-arg={argument}"));
    }
    for export in EXPORTS {
        command.arg(format!("-Clink-arg=/export:{export}"));
    }
    invoke(
        command
            .arg(source().join("hosts/frame.rs"))
            .arg("-o")
            .arg(options.out.join("frame-original.dll"))
            .env("LIB", &options.lib_dirs),
    )?;
    ensure!(
        Pe::read(&options.out.join("frame-original.dll"))?
            .exports()?
            .contains_key("__chkstk"),
        "frame fixture lost the real compiler stack-probe symbol"
    );
    Ok(())
}

pub fn produce(options: &Options) -> Result<()> {
    let directory = options.out.join("frame-negative");
    std::fs::create_dir_all(&directory)?;
    let sdk = source()
        .join("../../crates/kamy-sdk")
        .to_string_lossy()
        .replace('\\', "/");
    std::fs::write(
        directory.join("Cargo.toml"),
        format!(
            "[package]\nname = \"sdk-rebuild-dynamic-frame\"\nversion = \"0.0.0\"\nedition = \"2024\"\npublish = false\n[workspace]\n[lib]\npath = \"lib.rs\"\ncrate-type = [\"staticlib\"]\n[dependencies]\nkamy-sdk = {{ path = {sdk:?} }}\n"
        ),
    )?;
    std::fs::write(
        directory.join("lib.rs"),
        r##"#![no_std]
use core::ffi::c_void;

#[inline(never)]
unsafe extern "system" fn initialize(_: *mut c_void, table_start: *mut c_void, _: *mut c_void) -> i32 {
    let size = ((table_start as usize) & 0x3f0) + 16;
    unsafe {
        core::arch::asm!(
            "sub rsp, {size}",
            "mov byte ptr [rsp], 0",
            "add rsp, {size}",
            size = in(reg) size,
        );
    }
    0
}

kamy_sdk::plugin!(initialize);
"##,
    )?;
    invoke(
        Command::new(&options.kamy)
            .args(["plugin", "build", "--manifest-path"])
            .arg(directory.join("Cargo.toml"))
            .arg("--output")
            .arg(options.out.join("frame-dynamic.dll"))
            .arg("--linker")
            .arg(&options.linker)
            .env("CARGO", &options.cargo)
            .env("RUSTC", &options.rustc)
            .env("KAMY_LLVM_TOOLS_DIR", &options.llvm_tools),
    )?;
    std::fs::write(
        options.out.join("frame-dynamic.yml"),
        "version: '1'\nmodule_settings:\n  injection:\n    enabled: true\n    mode: inline\n    plugins:\n      - name: dynamic_frame\n        path: frame-dynamic.dll\n",
    )?;
    Ok(())
}

fn reject_dynamic(options: &Options) -> Result<()> {
    let output = options.out.join("frame-dynamic-rejected.exe");
    ensure!(
        !output.exists(),
        "dynamic-frame rejection target already exists"
    );
    let result = capture(
        Command::new(&options.kamy)
            .arg("protect")
            .arg(options.out.join("host-original.exe"))
            .arg("--output")
            .arg(&output)
            .arg("--profile")
            .arg(options.out.join("frame-dynamic.yml"))
            .arg("--ssa-identity"),
    )?;
    ensure!(
        !result.status.success(),
        "unprovable authored dynamic frame falsely succeeded"
    );
    ensure!(
        !output.exists(),
        "dynamic frame failure emitted a partially protected output"
    );
    let diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    ensure!(
        diagnostic
            .lines()
            .any(|line| line.contains("plugin dynamic_frame::")
                && line
                    .trim_end()
                    .ends_with("cannot pass SSA/codegen: FrameDynamic")),
        "dynamic frame did not fail with its source-qualified semantic cause: {diagnostic}"
    );
    println!("PASS frame-dynamic reason=FrameDynamic output_absent=1");
    Ok(())
}

fn inspect(original: &Pe, output: &Path, report: &Path, identity: bool) -> Result<String> {
    let pe = Pe::read(output)?;
    let value: Value = serde_json::from_slice(&std::fs::read(report)?)?;
    ensure!(
        value["schema"] == "kamy-link-report" && value["version"] == 1,
        "frame fixture has an invalid link report"
    );
    let functions = value["functions"]
        .as_array()
        .context("frame report lacks functions")?;
    let placements = value["placements"]
        .as_array()
        .context("frame report lacks placements")?;
    let exports = pe.exports()?;
    let original_exports = original.exports()?;
    let runtime = pe.runtime_ranges()?;
    let mut ranges = Vec::new();
    let mut transformed = 0;
    for &name in EXPORTS.iter().filter(|name| **name != "DllMain") {
        let source = *original_exports
            .get(name)
            .with_context(|| format!("missing original {name}"))?;
        let mut matching = functions.iter().filter(|function| {
            function["symbol"]["origin"] == "host"
                && function["symbol"]["host_source_rva"].as_u64() == Some(u64::from(source))
        });
        let function = matching
            .next()
            .with_context(|| format!("frame report omitted {name}"))?;
        ensure!(
            matching.next().is_none(),
            "duplicate frame source identity for {name}"
        );
        ensure!(
            ["selected", "eligible", "lowered"]
                .iter()
                .all(|field| function[*field] == true),
            "frame function was skipped or rejected: {name}: {function}"
        );
        let changed = function["transformed"]
            .as_bool()
            .context("missing frame transform outcome")?;
        let intensity = function["intensity"]
            .as_f64()
            .context("missing frame intensity")?;
        crate::report::inspect_allocation(
            function,
            matches!(name, "frame_large" | "frame_recursive" | "frame_saves"),
        )?;
        ensure!(
            if identity {
                !changed && intensity == 0.0
            } else {
                changed && intensity == 1.0
            },
            "frame function reduced requested intensity: {name}: {function}"
        );
        transformed += usize::from(changed);
        if let Some(minimum) = match name {
            "frame_recursive" => Some(4096),
            "frame_large" => Some(24576),
            "frame_saves" => Some(16384),
            _ => None,
        } {
            ensure!(
                function["allocation"]["original_frame_size"]
                    .as_u64()
                    .is_some_and(|size| size >= minimum),
                "original address-taken frame object disappeared from the concrete layout: {name}"
            );
        }
        let mut owners = placements.iter().filter(|placement| {
            placement["symbol"] == function["symbol"] && placement["ownership"] != "retired"
        });
        let owner = owners
            .next()
            .context("frame source has no final placement")?;
        ensure!(
            owners.next().is_none(),
            "frame source has multiple final placements"
        );
        let begin = u32::try_from(owner["rva"].as_u64().context("missing frame RVA")?)?;
        let size = u32::try_from(owner["size"].as_u64().context("missing frame size")?)?;
        let end = begin
            .checked_add(size)
            .context("frame function extent overflow")?;
        ensure!(
            size != 0 && end <= pe.image_size && exports.get(name) == Some(&begin),
            "export is not bound to final source-qualified frame placement: {name}"
        );
        let pc = native::decode_prologue(pe.slice(begin, size as usize)?, begin)?.pc;
        ensure!(
            runtime
                .iter()
                .any(|(start, finish, _)| *start <= pc && pc < *finish),
            "frame body has no active runtime record: {name}"
        );
        ranges.push(format!("host@{begin}:{pc}:{end}"));
    }
    ensure!(
        identity || transformed > 0,
        "requested MBA did not transform the frame fixture"
    );
    println!(
        "frame_report identity={identity} lowered={} transformed={transformed}",
        ranges.len()
    );
    Ok(ranges.join(","))
}

pub fn run(options: &Options) -> Result<()> {
    reject_dynamic(options)?;
    let original_path = options.out.join("frame-original.dll");
    let original = Pe::read(&original_path)?;
    run_target(
        &std::env::current_exe()?,
        vec![
            "probe-frame".to_owned(),
            original_path.to_string_lossy().into_owned(),
            String::new(),
        ],
        Vec::new(),
        false,
    )?;
    let profile = options.out.join("frame.yml");
    let ordered = include_str!("../../../crates/kamy-cli/tests/fixtures/profiles/ordered-mba.yml");
    let mut yaml = ordered.to_owned();
    yaml.push_str("  symbols:\n");
    let exports = original.exports()?;
    for &name in EXPORTS.iter().filter(|name| **name != "DllMain") {
        let rva = *exports
            .get(name)
            .with_context(|| format!("frame host lacks {name}"))?;
        yaml.push_str(&format!(
            "  - !Address {:#x}\n",
            original.image_base + u64::from(rva)
        ));
    }
    std::fs::write(&profile, yaml)?;
    for identity in [true, false] {
        let stem = if identity {
            "frame-identity"
        } else {
            "frame-mba"
        };
        let output = options.out.join(format!("{stem}.dll"));
        let report = options.out.join(format!("{stem}.json"));
        let mut command = Command::new(&options.kamy);
        command
            .arg("protect")
            .arg(&original_path)
            .arg("--output")
            .arg(&output)
            .arg("--profile")
            .arg(&profile)
            .arg("--link-report")
            .arg(&report);
        if identity {
            command.arg("--ssa-identity");
        }
        let protected = capture(&mut command)?;
        ensure!(
            protected.status.success(),
            "mandatory frame fixture protection failed ({})",
            protected.status
        );
        let ranges = inspect(&original, &output, &report, identity)?;
        run_target(
            &std::env::current_exe()?,
            vec![
                "probe-frame".to_owned(),
                output.to_string_lossy().into_owned(),
                ranges,
            ],
            Vec::new(),
            false,
        )?;
        println!("PASS {stem} execution=1 aslr=1");
    }
    Ok(())
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryW(path: *const u16) -> *mut c_void;
    fn FreeLibrary(module: *mut c_void) -> i32;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    fn GetLastError() -> u32;
    fn VirtualAlloc(address: *mut c_void, size: usize, kind: u32, protection: u32) -> *mut c_void;
    fn VirtualFree(address: *mut c_void, size: usize, kind: u32) -> i32;
}

unsafe fn symbol(image: *mut c_void, name: &std::ffi::CStr) -> Result<*mut c_void> {
    let pointer = unsafe { GetProcAddress(image, name.as_ptr().cast()) };
    ensure!(!pointer.is_null(), "frame export is missing: {name:?}");
    Ok(pointer)
}

pub fn probe(arguments: &[String]) -> Result<()> {
    ensure!(
        arguments.len() == 2,
        "probe-frame requires DLL path and source-qualified unwind ranges"
    );
    let path = Path::new(&arguments[0]);
    let pe = Pe::read(path)?;
    let wide: Vec<u16> = path
        .as_os_str()
        .to_string_lossy()
        .encode_utf16()
        .chain(Some(0))
        .collect();
    unsafe {
        let reservation = VirtualAlloc(
            pe.image_base as *mut c_void,
            pe.image_size as usize,
            0x2000,
            1,
        );
        ensure!(
            reservation as u64 == pe.image_base,
            "cannot reserve frame preferred image base: {}",
            GetLastError()
        );
        let image = LoadLibraryW(wide.as_ptr());
        ensure!(
            !image.is_null(),
            "cannot load frame fixture: {}",
            GetLastError()
        );
        ensure!(
            image as u64 != pe.image_base,
            "frame fixture did not relocate"
        );
        let mix6: unsafe extern "system" fn(u64, u64, u64, u64, u64, u64) -> u64 =
            core::mem::transmute(symbol(image, c"frame_mix6")?);
        let stack6: unsafe extern "system" fn(u64) -> u64 =
            core::mem::transmute(symbol(image, c"frame_stack6")?);
        let pinned: unsafe extern "system" fn(u64) -> u64 =
            core::mem::transmute(symbol(image, c"frame_pinned")?);
        let mixed: unsafe extern "system" fn(u64, f64, u64, f64, u64, f64) -> f64 =
            core::mem::transmute(symbol(image, c"frame_mixed")?);
        let recursive: unsafe extern "system" fn(u64, u64, *mut usize) -> u64 =
            core::mem::transmute(symbol(image, c"frame_recursive")?);
        let large: unsafe extern "system" fn(u64) -> u64 =
            core::mem::transmute(symbol(image, c"frame_large")?);
        ensure!(
            mix6(2, 3, 5, 7, 11, 13) == 18_446_744_073_709_551_593,
            "incoming six-GPR argument oracle failed"
        );
        ensure!(
            stack6(17) == 892,
            "address-taken object/outgoing six-argument oracle failed"
        );
        ensure!(
            pinned(17) == 18_446_744_073_709_550_642,
            "call-produced live-across-call oracle failed"
        );
        ensure!(
            mixed(3, 3.25, 5, -7.0, 9, 2.5).to_bits() == (-1.25f64).to_bits(),
            "mixed register/stack ABI oracle failed"
        );
        let mut trace = [0usize; 65];
        ensure!(
            recursive(64, 17, trace.as_mut_ptr()) == 57_994,
            "recursive original-object oracle failed"
        );
        ensure!(
            trace.iter().all(|address| *address != 0),
            "recursive fixture skipped a depth"
        );
        let strides: Vec<_> = trace
            .windows(2)
            .map(|pair| {
                pair[0]
                    .checked_sub(pair[1])
                    .context("recursive stack did not descend")
            })
            .collect::<Result<_>>()?;
        ensure!(
            strides.iter().all(|stride| (4096..8192).contains(stride)),
            "recursive original frame duplicated or overlapped: {strides:?}"
        );
        ensure!(
            large(17) == 33_071_616,
            "large guard-page frame oracle failed"
        );
        let saves: unsafe extern "system" fn(u64) -> u64 =
            core::mem::transmute(symbol(image, c"frame_saves")?);
        ensure!(saves(17) == 118, "large GPR/XMM save fixture oracle failed");
        if !arguments[1].is_empty() {
            native::check_ranges(image.cast(), pe.image_size, &arguments[1])?;
        }
        ensure!(FreeLibrary(image) != 0, "frame FreeLibrary failed");
        ensure!(
            VirtualFree(reservation, 0, 0x8000) != 0,
            "frame image reservation release failed"
        );
        println!("frame_runtime=PASS depth=64 original_object=4096 large_object=24576 aslr=1");
    }
    Ok(())
}
