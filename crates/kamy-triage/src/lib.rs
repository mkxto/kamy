//! Agent triage tooling for the kamy protector pipeline.
//!
//! Triage tools:
//! - [`protect_identity`]: canonical SSA-identity protect of a PE, returning
//!   the raw linker [`kamy_link::Report`]; an optional [`FunctionSelector`]
//!   restricts which functions are SSA-lowered.
//! - [`dump_function`]: human-readable dump of a single function's IR at a
//!   chosen pipeline [`Stage`] (lift / SSA / optimize / regalloc).
//! - [`dump_native`]: exact file-backed PE range with RVA, preferred VA, bytes
//!   and decoded Intel-syntax operands, without discovery or lowering.
//! - [`bisect`]: delta-debug the set of SSA-lowered functions down to a minimal
//!   failing subset, then capture the faulting address via a traced run.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter};
use kamy_core::ir::{IrBlock, IrFunction};
use kamy_core::{FunctionSelector, Rva, SymbolId};
use kamy_disasm::discover_functions;
use kamy_lift::LiftResult;
use kamy_link::Report;
use kamy_pe::PeFile;

/// Canonical SSA-identity protect: lift → SSA → optimize → regalloc → isel →
/// encode with an identity transform (no obfuscation). `selector` restricts
/// which host functions are SSA-lowered. Deselected bodies remain resident;
/// their known references to moved code may still be patched. Writes the image
/// to `output` and returns its linker [`Report`].
pub fn protect_identity(
    input: &Path,
    output: &Path,
    selector: Option<&FunctionSelector>,
) -> anyhow::Result<Report> {
    let bytes = std::fs::read(input).with_context(|| format!("reading {}", input.display()))?;
    let pe = PeFile::parse(&bytes).with_context(|| format!("parsing {}", input.display()))?;

    let mut module = pe.to_module();
    let seeds = pe.seeds();
    module.functions = discover_functions(&module, &seeds);

    let cc = kamy_link::build_callconv(&pe, &module)?;
    let mut identity =
        |_: &SymbolId, _: &mut IrFunction, _: f32| Ok(kamy_link::TransformOutcome::default());
    let opts = kamy_link::Options {
        selector: selector.cloned(),
        ..Default::default()
    };
    let (image, report) = kamy_link::protect(
        &pe,
        &module,
        &module.functions,
        &opts,
        &cc,
        &mut identity,
        kamy_link::module::Injection {
            plugins: &[],
            mode: kamy_link::module::EntryMode::InitTable,
        },
    )?;
    std::fs::write(output, &image).with_context(|| format!("writing {}", output.display()))?;
    Ok(report)
}

/// Pipeline stage up to which [`dump_function`] runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Lift,
    Ssa,
    Optimize,
    Regalloc,
}

/// Decode exactly `size` file-backed bytes at `rva` in the supplied PE.
/// Coordinates must come from that exact original/protected image's map/report;
/// this does not infer function extents or interpret authored module identities.
/// VAs use the preferred PE image base, not a live process's ASLR load address.
pub fn dump_native(input: &Path, rva: Rva, size: u32) -> anyhow::Result<String> {
    let bytes = std::fs::read(input).with_context(|| format!("reading {}", input.display()))?;
    let pe = PeFile::parse(&bytes).with_context(|| format!("parsing {}", input.display()))?;
    dump_native_range(&pe, rva, size).with_context(|| {
        format!(
            "native dump of {} at RVA {rva}, size {size}",
            input.display()
        )
    })
}

fn dump_native_range(pe: &PeFile, rva: Rva, size: u32) -> anyhow::Result<String> {
    anyhow::ensure!(size != 0, "native byte count must be nonzero");
    let start = rva.get();
    let end = start
        .checked_add(size)
        .context("native RVA range overflow")?;
    let (index, section) = pe
        .section_headers()
        .iter()
        .enumerate()
        .find(|(_, section)| {
            start >= section.rva
                && u64::from(start) < u64::from(section.rva) + u64::from(section.raw_size)
        })
        .with_context(|| format!("RVA {rva} is not file-backed section storage"))?;
    let offset = start - section.rva;
    anyhow::ensure!(
        u64::from(offset) + u64::from(size) <= u64::from(section.raw_size),
        "native range {rva}..{end:#x} exceeds file-backed section {:?}",
        section.name
    );
    let data = pe
        .section_data(index)
        .with_context(|| format!("file-backed section {:?} is truncated", section.name))?;
    let data = data
        .get(offset as usize..(u64::from(offset) + u64::from(size)) as usize)
        .context("requested native bytes are truncated")?;
    let base = pe.image_base();
    let va = base
        .checked_add(u64::from(start))
        .context("native VA overflow")?;
    base.checked_add(u64::from(end))
        .context("native VA range overflow")?;

    let mut out = String::new();
    writeln!(out, "native RVA {start:#010x}..{end:#010x}, size {size}")?;
    writeln!(
        out,
        "preferred_image_base: {base:#018x} (not a runtime ASLR address)"
    )?;
    writeln!(
        out,
        "RVA         VA                  bytes                                         instruction"
    )?;
    let mut decoder = Decoder::with_ip(64, data, va, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    formatter.options_mut().set_rip_relative_addresses(true);
    let mut operands = String::new();
    while decoder.can_decode() {
        let offset = decoder.position();
        let instruction = decoder.decode();
        let pc = start + offset as u32;
        anyhow::ensure!(
            !instruction.is_invalid(),
            "invalid or truncated x86-64 instruction at RVA {pc:#010x}, VA {:#018x} ({:?})",
            instruction.ip(),
            decoder.last_error()
        );
        operands.clear();
        formatter.format(&instruction, &mut operands);
        write!(out, "{pc:#010x}  {:#018x}  ", instruction.ip())?;
        for byte in &data[offset..decoder.position()] {
            write!(out, "{byte:02x} ")?;
        }
        for _ in instruction.len()..15 {
            out.push_str("   ");
        }
        writeln!(out, " {operands}")?;
    }
    Ok(out)
}

/// Run the per-function pipeline up to `stage` at an exact source-local entry.
/// Authored inputs use compiler symbols, operand provenance and native ABI;
/// ordinary host inputs retain conservative discovery.
pub fn dump_function(input: &Path, rva: Rva, stage: Stage) -> anyhow::Result<String> {
    let bytes = std::fs::read(input).with_context(|| format!("reading {}", input.display()))?;
    let pe = PeFile::parse(&bytes).with_context(|| format!("parsing {}", input.display()))?;
    if pe
        .section_headers()
        .iter()
        .any(|section| section.name == ".kmod")
    {
        let identity = input.display().to_string();
        let plugin = kamy_link::module::Plugin {
            name: identity.clone(),
            module: kamy_pe::module::AuthoredModule::parse(&bytes, &identity)
                .with_context(|| format!("authored provenance in {}", input.display()))?,
        };
        let source = kamy_link::module::AuthoredSource::new(&plugin)?;
        let prepared = source.function_at(rva, None)?;
        let result = kamy_lift::lift_function(
            source.module(),
            &prepared.function,
            &source,
            &prepared.references,
        );
        let mut out = String::new();
        writeln!(out, "source: {:?}", prepared.symbol.symbol)?;
        writeln!(
            out,
            "source_range: {}..{}",
            prepared.symbol.start, prepared.symbol.end
        )?;
        writeln!(out, "native_abi: {:?}", prepared.symbol.signature)?;
        writeln!(out, "operand_references:")?;
        for reference in &prepared.references {
            writeln!(out, "  {reference:?}")?;
        }
        return dump_result(result, rva, stage, out, true);
    }

    let mut module = pe.to_module();
    let seeds = pe.seeds();
    module.functions = discover_functions(&module, &seeds);

    let func = module
        .functions
        .iter()
        .find(|f| f.entry == rva)
        .with_context(|| format!("no function with entry {rva}"))?;

    let cc = kamy_link::build_callconv(&pe, &module)?;
    let result = kamy_lift::lift_function(&module, func, &cc, &[]);
    dump_result(result, rva, stage, String::new(), false)
}

fn dump_result(
    mut result: LiftResult,
    rva: Rva,
    stage: Stage,
    mut out: String,
    authored: bool,
) -> anyhow::Result<String> {
    if matches!(stage, Stage::Ssa | Stage::Optimize | Stage::Regalloc) {
        if let Err(reason) = kamy_lift::ssa::construct_ssa(&mut result) {
            writeln!(out, "function {rva} @ {stage:?}")?;
            write_header(&mut out, &result)?;
            write_ir(&mut out, &result.func)?;
            bail!("{out}concrete frame reconstruction failed: {reason}");
        }
        if authored {
            kamy_transforms::resolve_image_base_uses(&mut result.func, |offset| {
                Some(kamy_core::SymbolicExpression::Symbol {
                    symbol: SymbolId::HostImageBase,
                    addend: offset,
                })
            });
        }
    }
    if matches!(stage, Stage::Optimize | Stage::Regalloc) {
        kamy_transforms::optimize(&mut result.func);
    }

    writeln!(out, "function {rva} @ {stage:?}")?;
    if result.unsupported {
        writeln!(out, "unsupported: true")?;
        if authored {
            writeln!(out, "lowering rejection: UnsupportedInstruction")?;
        }
    }
    write_header(&mut out, &result)?;
    write_ir(&mut out, &result.func)?;

    if stage == Stage::Regalloc {
        match kamy_codegen::allocate_registers(&result.func, &result.rsp_chain, &result.reg_pins) {
            Ok(alloc) => write_regalloc(&mut out, &alloc)?,
            Err(reason) if authored => bail!("{out}register allocation failed: {reason}"),
            Err(reason) => bail!("register allocation failed: {reason}"),
        }
    }

    Ok(out)
}

fn write_header(out: &mut String, result: &LiftResult) -> anyhow::Result<()> {
    writeln!(out, "reg_pins:")?;
    let mut pins: Vec<_> = result.reg_pins.iter().collect();
    pins.sort_by_key(|(v, _)| v.0);
    for (v, p) in pins {
        writeln!(out, "  v{} -> {:?}", v.0, p)?;
    }
    let mut chain: Vec<u32> = result.rsp_chain.iter().map(|v| v.0).collect();
    chain.sort_unstable();
    let chain: Vec<String> = chain.iter().map(|id| format!("v{id}")).collect();
    writeln!(out, "rsp_chain: [{}]", chain.join(", "))?;
    Ok(())
}

fn write_ir(out: &mut String, func: &IrFunction) -> anyhow::Result<()> {
    writeln!(out, "entry: block{}", func.entry.0)?;
    writeln!(out, "next_value: {}", func.next_value)?;
    for b in &func.blocks {
        write_block(out, b)?;
    }
    Ok(())
}

fn write_block(out: &mut String, b: &IrBlock) -> anyhow::Result<()> {
    writeln!(out, "block{}:", b.id.0)?;
    for phi in &b.phis {
        let args: Vec<String> = phi
            .args
            .iter()
            .map(|(bid, v)| format!("(block{}, v{})", bid.0, v.0))
            .collect();
        writeln!(
            out,
            "  v{}: {:?} = phi [{}]",
            phi.dest.0,
            phi.ty,
            args.join(", ")
        )?;
    }
    for inst in &b.insts {
        let dest = match inst.dest {
            Some(d) => format!("v{} = ", d.0),
            None => String::new(),
        };
        let args: Vec<String> = inst.args.iter().map(|a| format!("v{}", a.0)).collect();
        writeln!(
            out,
            "  {}{:?} [{}] : {:?}",
            dest,
            inst.op,
            args.join(", "),
            inst.ty
        )?;
    }
    writeln!(out, "  term: {:?}", b.term)?;
    Ok(())
}

fn write_regalloc(out: &mut String, alloc: &kamy_codegen::RegAllocation) -> anyhow::Result<()> {
    writeln!(out, "allocation: memory-backed")?;
    writeln!(out, "frame: {:?}", alloc.frame)?;
    writeln!(out, "frame_size_limit: {}", kamy_core::MAX_FRAME_SIZE)?;
    writeln!(out, "scratch_gprs: {:?}", kamy_codegen::MEMORY_SCRATCH_GPRS)?;
    writeln!(out, "scratch_xmms: {:?}", kamy_codegen::MEMORY_SCRATCH_XMMS)?;
    writeln!(out, "memory_homes: {}", alloc.homes.len())?;
    let mut homes: Vec<_> = alloc.homes.iter().collect();
    homes.sort_by_key(|(value, _)| value.0);
    for (value, home) in homes {
        writeln!(out, "  v{} -> {home:?}", value.0)?;
    }
    writeln!(out, "entry_stack_offsets:")?;
    let mut offsets: Vec<_> = alloc.analysis.offsets.iter().collect();
    offsets.sort_by_key(|(value, _)| value.0);
    for (value, offset) in offsets {
        writeln!(out, "  v{} -> {offset:?}", value.0)?;
    }
    writeln!(out, "derived_stack_offsets:")?;
    let mut derived: Vec<_> = alloc.analysis.derived_offsets.iter().collect();
    derived.sort_by_key(|(value, _)| value.0);
    for (value, (base, offset)) in derived {
        writeln!(out, "  v{} -> v{} {offset:+}", value.0, base.0)?;
    }
    writeln!(out, "call_stack_deltas:")?;
    let mut calls: Vec<_> = alloc.analysis.call_deltas.iter().collect();
    calls.sort_by_key(|((block, instruction), _)| (block.0, *instruction));
    for ((block, instruction), delta) in calls {
        writeln!(out, "  block{} @{instruction} -> {delta}", block.0)?;
    }
    writeln!(out, "boundary_pins:")?;
    let mut a: Vec<_> = alloc.pins.iter().collect();
    a.sort_by_key(|(v, _)| v.0);
    for (v, p) in a {
        writeln!(out, "  v{} -> {:?}", v.0, p)?;
    }
    Ok(())
}

/// Result of [`bisect`].
pub struct BisectOutcome {
    /// Minimal set of SSA-lowered function entries that still reproduces the
    /// failure.
    pub culprit: Vec<Rva>,
    /// Number of SSA-lowering candidates considered (the all-lowered set).
    pub candidates: usize,
    /// Count of protect+test iterations performed.
    pub steps: usize,
    /// Final traced execution, using the same launch context as the probes.
    /// Callers must apply their probe oracle to this outcome too.
    pub replay: kamy_run::RunOutcome,
    /// Exact minimal-subset binary in its own retained directory, only when requested.
    pub artifact: Option<PathBuf>,
}

struct ArtifactDir {
    path: PathBuf,
    keep: bool,
}

impl ArtifactDir {
    fn new() -> anyhow::Result<Self> {
        Self::new_in(&std::env::temp_dir())
    }

    fn new_in(root: &Path) -> anyhow::Result<Self> {
        let mut id = 0u64;
        loop {
            let path = root.join(format!("kamy-triage-{}-{id}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path, keep: false }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => id += 1,
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("creating triage directory {}", path.display()));
                }
            }
        }
    }
}

impl Drop for ArtifactDir {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

/// Protect `input` restricted to `subset`, run `is_pass`, and report whether the
/// result still *fails* (the property delta-debugging minimizes). The protected
/// artifact is removed afterward.
fn still_fails(
    input: &Path,
    dir: &Path,
    subset: &[Rva],
    is_pass: &dyn Fn(&Path) -> anyhow::Result<bool>,
    counter: &mut u64,
    steps: &mut usize,
) -> anyhow::Result<bool> {
    *counter += 1;
    let out = dir.join(format!("probe-{counter}.exe"));
    let sel = FunctionSelector::only(subset.iter().copied());
    protect_identity(input, &out, Some(&sel))?;
    *steps += 1;
    let res = is_pass(&out);
    std::fs::remove_file(&out)
        .with_context(|| format!("removing triage probe {}", out.display()))?;
    Ok(!res?)
}

/// Delta-debug (ddmin) `candidates` to a 1-minimal subset that still fails.
fn ddmin(
    input: &Path,
    dir: &Path,
    candidates: Vec<Rva>,
    is_pass: &dyn Fn(&Path) -> anyhow::Result<bool>,
    counter: &mut u64,
    steps: &mut usize,
) -> anyhow::Result<Vec<Rva>> {
    let mut c = candidates;
    let mut n = 2usize;
    'outer: while c.len() >= 2 {
        let chunk = c.len().div_ceil(n);
        let mut chunks: Vec<&[Rva]> = Vec::new();
        let mut i = 0;
        while i < c.len() {
            let end = (i + chunk).min(c.len());
            chunks.push(&c[i..end]);
            i = end;
        }

        // Reduce to a single failing chunk.
        for ch in &chunks {
            if !ch.is_empty() && still_fails(input, dir, ch, is_pass, counter, steps)? {
                c = ch.to_vec();
                n = 2;
                continue 'outer;
            }
        }

        // Reduce to a failing complement (drop one chunk).
        for ch in &chunks {
            let complement: Vec<Rva> = c.iter().copied().filter(|r| !ch.contains(r)).collect();
            if !complement.is_empty()
                && still_fails(input, dir, &complement, is_pass, counter, steps)?
            {
                c = complement;
                n = (n - 1).max(2);
                continue 'outer;
            }
        }

        if n >= c.len() {
            break;
        }
        n = (2 * n).min(c.len());
    }
    Ok(c)
}

/// Localize an SSA-lowering regression. Confirms the empty-selection resident
/// baseline passes and the all-lowered build fails, then delta-debugs the
/// lowered-function set to a minimal failing subset. The final traced replay
/// changes only `run_options.exe`; callers must check `replay` with the same
/// oracle as `is_pass`. `keep` retains only that final protected binary.
pub fn bisect(
    input: &Path,
    run_options: &kamy_run::RunOptions,
    is_pass: &dyn Fn(&Path) -> anyhow::Result<bool>,
    keep: bool,
) -> anyhow::Result<BisectOutcome> {
    let mut dir = ArtifactDir::new()?;
    let mut steps = 0usize;
    let mut counter = 0u64;

    // (a) Empty-selection resident baseline: lower nothing. Must pass.
    counter += 1;
    let out_a = dir.path.join(format!("probe-{counter}.exe"));
    let empty = FunctionSelector::only(std::iter::empty());
    protect_identity(input, &out_a, Some(&empty))?;
    steps += 1;
    let res_a = is_pass(&out_a);
    std::fs::remove_file(&out_a)
        .with_context(|| format!("removing triage probe {}", out_a.display()))?;
    if !res_a? {
        bail!("empty-selection resident baseline already fails, bug is not in SSA lowering");
    }

    // (b) All-lowered build: selector None. Must fail; its report gives C.
    counter += 1;
    let out_b = dir.path.join(format!("probe-{counter}.exe"));
    let report = protect_identity(input, &out_b, None)?;
    steps += 1;
    let res_b = is_pass(&out_b);
    std::fs::remove_file(&out_b)
        .with_context(|| format!("removing triage probe {}", out_b.display()))?;
    let candidates: Vec<_> = report
        .ssa_lowered_symbols
        .iter()
        .filter_map(|symbol| match symbol {
            SymbolId::Host { rva } => Some(*rva),
            _ => None,
        })
        .collect();
    if res_b? {
        bail!("all-lowered passes, nothing to bisect");
    }

    // (c) Delta-debug to a minimal failing subset.
    let culprit = ddmin(
        input,
        &dir.path,
        candidates.clone(),
        is_pass,
        &mut counter,
        &mut steps,
    )?;

    // (d) Trace the minimal subset to capture the faulting address.
    let out_c = dir.path.join("replay.exe");
    let sel = FunctionSelector::only(culprit.iter().copied());
    protect_identity(input, &out_c, Some(&sel))?;
    steps += 1;
    let replay = replay(&out_c, run_options)?;
    let artifact = if keep {
        dir.keep = true;
        Some(out_c)
    } else {
        None
    };

    Ok(BisectOutcome {
        culprit,
        candidates: candidates.len(),
        steps,
        replay,
        artifact,
    })
}

/// Preserve the full invocation when tracing a protected replacement.
fn replay(exe: &Path, run_options: &kamy_run::RunOptions) -> anyhow::Result<kamy_run::RunOutcome> {
    let mut options = run_options.clone();
    options.exe = exe.to_path_buf();
    kamy_run::run_traced(&options)
}

#[cfg(test)]
mod tests {
    use super::{ArtifactDir, dump_native_range, replay};
    use kamy_run::RunOptions;
    use std::io::{Read as _, Write as _};
    use std::time::Duration;

    fn native_image(code: &[u8]) -> Vec<u8> {
        // One PE32+ section, with a virtual-only tail to distinguish BSS from bytes.
        let mut bytes = vec![0; 0x200 + code.len()];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
        bytes[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes[0xb0..0xb8].copy_from_slice(&0x140000000u64.to_le_bytes());
        bytes[0x188..0x18d].copy_from_slice(b".text");
        bytes[0x190..0x194].copy_from_slice(&(code.len() as u32 + 0x100).to_le_bytes());
        bytes[0x194..0x198].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[0x198..0x19c].copy_from_slice(&(code.len() as u32).to_le_bytes());
        bytes[0x19c..0x1a0].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[0x200..].copy_from_slice(code);
        bytes
    }

    #[test]
    fn native_dump_decodes_only_requested_bytes_with_exact_coordinates_and_operands() {
        let bytes = native_image(&[0x48, 0x8b, 0x44, 0x24, 0x28, 0xc3, 0x0f]);
        let pe = kamy_pe::PeFile::parse(&bytes).unwrap();
        let dump = dump_native_range(&pe, kamy_core::Rva::new(0x1000), 6).unwrap();
        let instructions: Vec<_> = dump.lines().filter(|line| line.starts_with("0x")).collect();
        assert_eq!(instructions.len(), 2, "{dump}");
        assert!(
            instructions[0].starts_with("0x00001000  0x0000000140001000"),
            "{dump}"
        );
        assert!(instructions[0].contains("48 8b 44 24 28"), "{dump}");
        assert!(instructions[0].contains("mov rax,[rsp+28h]"), "{dump}");
        assert!(
            instructions[1].starts_with("0x00001005  0x0000000140001005"),
            "{dump}"
        );
        assert!(instructions[1].contains("c3"), "{dump}");
        assert!(instructions[1].ends_with("ret"), "{dump}");
        assert!(dump.contains("not a runtime ASLR address"), "{dump}");
        // A non-entry subrange is allowed; no function discovery or boundary guessing.
        let tail = dump_native_range(&pe, kamy_core::Rva::new(0x1005), 1).unwrap();
        assert_eq!(
            tail.lines().filter(|line| line.starts_with("0x")).count(),
            1
        );
    }

    #[test]
    fn native_dump_rejects_zero_unmapped_virtual_and_cross_section_ranges() {
        let pe = kamy_pe::PeFile::parse(&native_image(&[0x90, 0xc3])).unwrap();
        for (rva, size, expected) in [
            (0x1000, 0, "nonzero"),
            (u32::MAX, 1, "RVA range overflow"),
            (0, 1, "not file-backed"),
            (0x2000, 1, "not file-backed"),
            (0x1002, 1, "not file-backed"),
            (0x1001, 2, "exceeds file-backed section"),
        ] {
            let error = dump_native_range(&pe, kamy_core::Rva::new(rva), size).unwrap_err();
            assert!(
                error.to_string().contains(expected),
                "{rva:#x}+{size}: {error:#}"
            );
        }
    }

    #[test]
    fn native_dump_rejects_truncated_file_and_invalid_or_partial_instructions() {
        let mut bytes = native_image(&[0x90, 0xc3]);
        bytes.pop();
        let pe = kamy_pe::PeFile::parse(&bytes).unwrap();
        let error = dump_native_range(&pe, kamy_core::Rva::new(0x1000), 2).unwrap_err();
        assert!(error.to_string().contains("truncated"), "{error:#}");
        for code in [&[0x48, 0x8b][..], &[0x06][..]] {
            let pe = kamy_pe::PeFile::parse(&native_image(code)).unwrap();
            let error =
                dump_native_range(&pe, kamy_core::Rva::new(0x1000), code.len() as u32).unwrap_err();
            assert!(
                error.to_string().contains("invalid or truncated"),
                "{error:#}"
            );
            assert!(error.to_string().contains("RVA 0x00001000"), "{error:#}");
            assert!(
                error.to_string().contains("VA 0x0000000140001000"),
                "{error:#}"
            );
        }
    }

    #[test]
    fn native_dump_rejects_preferred_va_overflow() {
        let mut bytes = native_image(&[0x90, 0xc3]);
        bytes[0xb0..0xb8].copy_from_slice(&(u64::MAX - 0x1000).to_le_bytes());
        let pe = kamy_pe::PeFile::parse(&bytes).unwrap();
        let error = dump_native_range(&pe, kamy_core::Rva::new(0x1000), 1).unwrap_err();
        assert!(error.to_string().contains("VA range overflow"), "{error:#}");
        let error = dump_native_range(&pe, kamy_core::Rva::new(0x1001), 1).unwrap_err();
        assert!(error.to_string().contains("VA overflow"), "{error:#}");
    }

    #[test]
    fn final_replay_preserves_stdin_args_environment_and_working_directory() {
        if std::env::var("KAMY_REPLAY_CHILD").as_deref() == Ok("context") {
            let args: Vec<_> = std::env::args().collect();
            // The harness accepts arbitrary --skip values, so this also carries child data.
            let offset_file = args
                .windows(2)
                .find(|pair| pair[0] == "--skip")
                .map(|pair| &pair[1])
                .expect("offset filename argument");
            let mut input = String::new();
            std::io::stdin().read_to_string(&mut input).unwrap();
            let value: i32 = input.trim().parse().unwrap();
            let offset: i32 = std::fs::read_to_string(offset_file)
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            let environment: i32 = std::env::var("KAMY_REPLAY_OFFSET")
                .unwrap()
                .parse()
                .unwrap();
            let result = value + offset + environment;
            println!("\nKAMY_REPLAY_RESULT={result}");
            std::io::stdout().flush().unwrap();
            std::process::exit(result);
        }

        let dir = ArtifactDir::new().unwrap();
        std::fs::write(dir.path.join("offset.txt"), "5").unwrap();
        let executable = dir.path.join("probe-1.exe");
        std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        let options = RunOptions {
            // Only this field may be replaced by replay().
            exe: dir.path.join("does-not-exist.exe"),
            args: vec![
                "--exact".into(),
                "tests::final_replay_preserves_stdin_args_environment_and_working_directory".into(),
                "--nocapture".into(),
                "--quiet".into(),
                "--skip".into(),
                "offset.txt".into(),
            ],
            stdin: b"30\n".to_vec(),
            env: vec![
                ("KAMY_REPLAY_CHILD".into(), "context".into()),
                ("KAMY_REPLAY_OFFSET".into(), "7".into()),
            ],
            cwd: Some(dir.path.clone()),
            timeout: Duration::from_secs(10),
        };
        let result = replay(&executable, &options).unwrap();
        std::fs::remove_file(&executable)
            .expect("a completed traced process must release its executable immediately");
        assert!(!result.timed_out, "{result:?}");
        assert!(result.fault.is_none(), "{result:?}");
        assert_eq!(result.exit_code, Some(42), "{result:?}");
        assert!(
            result
                .stdout
                .split(|byte| *byte == b'\n')
                .any(|line| { line.trim_ascii_end() == b"KAMY_REPLAY_RESULT=42" }),
            "{result:?}"
        );
    }

    #[test]
    fn final_replay_enforces_the_probe_timeout() {
        if std::env::var("KAMY_REPLAY_CHILD").as_deref() == Ok("timeout") {
            std::fs::write("ready", b"started").unwrap();
            std::thread::sleep(Duration::from_secs(60));
            std::process::exit(0);
        }

        let dir = ArtifactDir::new().unwrap();
        let executable = dir.path.join("probe-1.exe");
        std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        let options = RunOptions {
            exe: dir.path.join("does-not-exist.exe"),
            args: vec![
                "--exact".into(),
                "tests::final_replay_enforces_the_probe_timeout".into(),
                "--nocapture".into(),
                "--quiet".into(),
            ],
            stdin: b"nonempty input\n".to_vec(),
            env: vec![("KAMY_REPLAY_CHILD".into(), "timeout".into())],
            cwd: Some(dir.path.clone()),
            timeout: Duration::from_secs(5),
        };
        let result = replay(&executable, &options).unwrap();
        std::fs::remove_file(&executable)
            .expect("a timed-out traced process must release its executable immediately");
        assert_eq!(
            std::fs::read(dir.path.join("ready")).unwrap(),
            b"started",
            "child must reach its blocking operation before the timeout"
        );
        assert!(result.timed_out, "{result:?}");
        assert!(result.fault.is_none(), "{result:?}");
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn faulted_replay_releases_its_executable_and_preserves_the_exception() {
        if std::env::var("KAMY_REPLAY_CHILD").as_deref() == Ok("fault") {
            std::fs::write("ready", b"started").unwrap();
            // SAFETY: this child deliberately executes UD2 to raise an actual
            // unhandled native illegal-instruction exception, not a Rust panic.
            unsafe { std::arch::asm!("ud2", options(noreturn, nostack)) };
        }

        let dir = ArtifactDir::new().unwrap();
        let executable = dir.path.join("probe-1.exe");
        std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        let options = RunOptions {
            exe: dir.path.join("does-not-exist.exe"),
            args: vec![
                "--exact".into(),
                "tests::faulted_replay_releases_its_executable_and_preserves_the_exception".into(),
                "--nocapture".into(),
                "--quiet".into(),
            ],
            env: vec![("KAMY_REPLAY_CHILD".into(), "fault".into())],
            cwd: Some(dir.path.clone()),
            // Fault cleanup must remain bounded even with no execution timeout.
            timeout: Duration::ZERO,
            ..Default::default()
        };
        let result = replay(&executable, &options).unwrap();
        std::fs::remove_file(&executable)
            .expect("a faulted traced process must release its executable immediately");
        assert_eq!(std::fs::read(dir.path.join("ready")).unwrap(), b"started");
        assert!(!result.timed_out, "{result:?}");
        let fault = result.fault.expect("the native fault must be observed");
        assert_eq!(fault.code, 0xc000_001d, "{result:?}");
        assert_eq!(result.exit_code, Some(fault.code as i32), "{result:?}");
        assert_ne!(fault.image_base, 0, "{result:?}");
        assert!(fault.address >= fault.image_base, "{result:?}");
        assert_eq!(fault.rva, fault.address - fault.image_base, "{result:?}");
    }

    #[test]
    fn new_invocation_preserves_preexisting_retained_evidence() {
        let root = ArtifactDir::new().unwrap();
        // Reproduce a retained directory from an earlier process with the same PID.
        let retained = root
            .path
            .join(format!("kamy-triage-{}-0", std::process::id()));
        std::fs::create_dir(&retained).unwrap();
        let evidence = retained.join("replay.exe");
        std::fs::write(&evidence, b"retained evidence").unwrap();

        let probe_dir;
        {
            let invocation = ArtifactDir::new_in(&root.path).unwrap();
            probe_dir = invocation.path.clone();
            std::fs::write(invocation.path.join("probe-1.exe"), b"partial probe").unwrap();
            std::fs::write(invocation.path.join("replay.exe"), b"new replay").unwrap();
        }

        assert!(
            !probe_dir.exists(),
            "unretained invocation must clean its files"
        );
        assert_eq!(std::fs::read(evidence).unwrap(), b"retained evidence");
        assert!(retained.is_dir());
    }
}
