//! Agent triage tooling for the kamy protector pipeline.
//!
//! Three tools:
//! - [`protect_identity`]: canonical SSA-identity protect of a PE, returning
//!   the raw linker [`kamy_link::Report`]; an optional [`FunctionSelector`]
//!   restricts which functions are SSA-lowered.
//! - [`dump_function`]: human-readable dump of a single function's IR at a
//!   chosen pipeline [`Stage`] (lift / SSA / optimize / regalloc).
//! - [`bisect`]: delta-debug the set of SSA-lowered functions down to a minimal
//!   failing subset, then capture the faulting address via a traced run.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
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
    /// Fault captured by a traced run of the minimal-subset protect, if any.
    pub fault: Option<kamy_run::Fault>,
}

fn temp_path(n: u64) -> PathBuf {
    std::env::temp_dir().join(format!("kamy-triage-{}-{n}.bin", std::process::id()))
}

/// Protect `input` restricted to `subset`, run `is_pass`, and report whether the
/// result still *fails* (the property delta-debugging minimizes). The protected
/// artifact is removed afterward.
fn still_fails(
    input: &Path,
    subset: &[Rva],
    is_pass: &dyn Fn(&Path) -> anyhow::Result<bool>,
    counter: &mut u64,
    steps: &mut usize,
) -> anyhow::Result<bool> {
    *counter += 1;
    let out = temp_path(*counter);
    let sel = FunctionSelector::only(subset.iter().copied());
    protect_identity(input, &out, Some(&sel))?;
    *steps += 1;
    let res = is_pass(&out);
    let _ = std::fs::remove_file(&out);
    Ok(!res?)
}

/// Delta-debug (ddmin) `candidates` to a 1-minimal subset that still fails.
fn ddmin(
    input: &Path,
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
            if !ch.is_empty() && still_fails(input, ch, is_pass, counter, steps)? {
                c = ch.to_vec();
                n = 2;
                continue 'outer;
            }
        }

        // Reduce to a failing complement (drop one chunk).
        for ch in &chunks {
            let complement: Vec<Rva> = c.iter().copied().filter(|r| !ch.contains(r)).collect();
            if !complement.is_empty() && still_fails(input, &complement, is_pass, counter, steps)? {
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

/// Localize an SSA-lowering regression. Confirms the verbatim baseline passes
/// and the all-lowered build fails, delta-debugs the lowered-function set to a
/// minimal failing subset, then traces that subset to capture the fault.
pub fn bisect(
    input: &Path,
    is_pass: &dyn Fn(&Path) -> anyhow::Result<bool>,
) -> anyhow::Result<BisectOutcome> {
    let mut steps = 0usize;
    let mut counter = 0u64;

    // (a) Verbatim baseline: lower nothing. Must pass.
    counter += 1;
    let out_a = temp_path(counter);
    let empty = FunctionSelector::only(std::iter::empty());
    protect_identity(input, &out_a, Some(&empty))?;
    steps += 1;
    let res_a = is_pass(&out_a);
    let _ = std::fs::remove_file(&out_a);
    if !res_a? {
        bail!("verbatim baseline already fails, bug is not in SSA lowering");
    }

    // (b) All-lowered build: selector None. Must fail; its report gives C.
    counter += 1;
    let out_b = temp_path(counter);
    let report = protect_identity(input, &out_b, None)?;
    steps += 1;
    let res_b = is_pass(&out_b);
    let _ = std::fs::remove_file(&out_b);
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
    let culprit = ddmin(input, candidates.clone(), is_pass, &mut counter, &mut steps)?;

    // (d) Trace the minimal subset to capture the faulting address.
    counter += 1;
    let out_c = temp_path(counter);
    let sel = FunctionSelector::only(culprit.iter().copied());
    protect_identity(input, &out_c, Some(&sel))?;
    steps += 1;
    let opts = kamy_run::RunOptions {
        exe: out_c.clone(),
        ..Default::default()
    };
    let outcome = kamy_run::run_traced(&opts);
    let _ = std::fs::remove_file(&out_c);
    let fault = outcome?.fault;

    Ok(BisectOutcome {
        culprit,
        candidates: candidates.len(),
        steps,
        fault,
    })
}
