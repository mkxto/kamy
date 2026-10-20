//! Relocating linker: move selected functions into a new section, leave a thunk
//! at each original entry, scrub the vacated body, and rebuild the PE.

use anyhow::Context;
use kamy_codegen::{relocate, thunk};
use kamy_core::ir::{CallingConvLookup, IrFunction};
use kamy_core::{Function, Module, RejectionReason, Rva, SectionFlags};
use kamy_disasm::function_instructions;
use kamy_pe::{BytePatch, DirectoryUpdate, NewSection, PeEdits, PeFile};
use std::collections::{BTreeMap, HashMap, HashSet};

const ENDBR64: [u8; 4] = [0xF3, 0x0F, 0x1E, 0xFA];
const INT3: u8 = 0xCC;
const NEAR_JMP_LEN: u32 = 5;
const FUNCTION_ALIGN: u32 = 16;

pub struct Options {
    pub code_section: String,
    pub pdata_section: String,
    pub xdata_section: String,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            code_section: ".kamy".into(),
            pdata_section: ".kamypd".into(),
            xdata_section: ".kamyxd".into(),
        }
    }
}

pub struct Report {
    pub moved: Vec<Rva>,
    pub rejected: Vec<(Rva, RejectionReason)>,
    pub ssa_lowered: usize,
}

#[derive(Clone)]
struct PrologueShape {
    pushed: Vec<iced_x86::Register>,
    stack_alloc: u32,
}

struct Moved {
    entry: Rva,
    new_rva: u32,
    new_len: u32,
    unwind: Option<Vec<u8>>,
}

/// Relocation-only path (Phase 1).
pub fn protect(
    pe: &PeFile,
    module: &Module,
    functions: &[Function],
    opts: &Options,
) -> anyhow::Result<(Vec<u8>, Report)> {
    protect_inner(pe, module, functions, opts, |module, func, base, new_va| {
        let instrs = function_instructions(module, func);
        Ok((relocate(&instrs, base + u64::from(new_va))?, Err(None)))
    })
}

/// SSA path with IR-level transforms. A function that cannot be SSA-lowered
/// (register pressure, unsupported instruction/flags, self-recursion) is
/// rejected in place — verbatim relocation is banned, since copying a function
/// unchanged applies no protection and only risks relocation bugs. Only
/// SSA-lowered (and switch-retargeted) functions are moved.
pub fn protect_with_transforms(
    pe: &PeFile,
    module: &Module,
    functions: &[Function],
    opts: &Options,
    cc: &dyn CallingConvLookup,
    transform: &mut dyn FnMut(&mut IrFunction, f32),
) -> anyhow::Result<(Vec<u8>, Report)> {
    protect_inner(
        pe,
        module,
        functions,
        opts,
        |module, func, base, new_rva| {
            let new_va = base + u64::from(new_rva);
            match ssa_body(module, func, cc, transform, base, new_va) {
                Ok((body, shape)) => Ok((body, Ok(shape))),
                Err(reason) => Ok((Vec::new(), Err(Some(reason)))),
            }
        },
    )
}

fn ssa_body(
    module: &Module,
    func: &Function,
    cc: &dyn CallingConvLookup,
    transform: &mut dyn FnMut(&mut IrFunction, f32),
    base: u64,
    new_va: u64,
) -> Result<(Vec<u8>, PrologueShape), RejectionReason> {
    // D28 pressure ladder: when the zero-spill allocator overflows under a
    // transform, retry at reduced intensity before giving up. Re-lift per
    // attempt so each intensity sees a clean IR. The non-pressure rejects
    // (unsupported / unsupported-flags / self-recursive) are intensity-
    // invariant, so they surface on the first attempt and short-circuit;
    // only `RegisterPressure` walks the ladder, relocating verbatim (the
    // caller's fallback) only after intensity 0.0 still fails.
    const INTENSITY_LADDER: [f32; 4] = [1.0, 0.5, 0.25, 0.0];
    let entry_va = base + u64::from(func.entry.get());
    for (i, &intensity) in INTENSITY_LADDER.iter().enumerate() {
        let mut result = kamy_lift::lift_function(module, func, cc);
        if result.unsupported {
            return Err(RejectionReason::UnsupportedInstruction);
        }
        kamy_lift::ssa::construct_ssa(&mut result);
        transform(&mut result.func, intensity);
        kamy_transforms::optimize(&mut result.func);
        if uses_unsupported_flags(&result.func) {
            return Err(RejectionReason::UnsupportedFlags);
        }
        if result.func.blocks.iter().any(|b| {
            b.insts
                .iter()
                .any(|i| matches!(i.op, kamy_core::ir::IrOp::Call { target } if target == entry_va))
        }) {
            return Err(RejectionReason::SelfRecursive);
        }

        match kamy_codegen::allocate_registers(
            &result.func,
            &kamy_codegen::CALLEE_SAVED_GPRS,
            &result.rsp_chain,
            &result.reg_pins,
        ) {
            Ok(alloc) => {
                let used = kamy_codegen::callee_saved_used(&alloc);
                let used_xmm = kamy_codegen::callee_saved_xmms_used(&alloc);
                let align_pad = if used.len() % 2 == 1 { 8 } else { 0 };
                let stack_alloc = align_pad + 16 * used_xmm.len() as u32;
                // The generated push/align prologue shifts RSP; a function that
                // reaches its caller's frame (shadow home / incoming stack arg)
                // would then address the pushed registers. Reject, don't
                // miscompile (D22) — only when a shift is actually emitted.
                let prologue_delta = 8 * used.len() as u32 + stack_alloc;
                if prologue_delta > 0 && accesses_caller_frame(&result.func, &result.rsp_chain) {
                    return Err(RejectionReason::CallerFrameAccess);
                }
                let instrs = kamy_codegen::select_instructions(
                    &result.func,
                    &alloc,
                    base,
                    new_va,
                    &used,
                    &used_xmm,
                );
                let shape = PrologueShape {
                    pushed: used,
                    stack_alloc,
                };
                return relocate(&instrs, new_va)
                    .map(|b| (b, shape))
                    .map_err(|_| RejectionReason::CodegenFailure);
            }
            Err(_) => {
                let msg = "register pressure";
                if let Some(&next) = INTENSITY_LADDER.get(i + 1) {
                    tracing::warn!(
                        func = %func.entry,
                        next_intensity = next,
                        reason = %msg,
                        "register pressure: retrying at reduced intensity"
                    );
                }
                continue;
            }
        }
    }
    tracing::debug!(func = %func.entry, "pressure ladder exhausted");
    Err(RejectionReason::RegisterPressure)
}

/// Variable-count shift condition flags (`shl cl;jc`, …) cannot be
/// reconstructed without CL, which the allocator does not model, so a function
/// that consumes one is relocated verbatim instead of miscompiled (reject-on-
/// ambiguity, D22). Add flags and constant-count shift flags ARE recomputable
/// (re-executed into a reserved scratch at the consumer) and so are no longer
/// rejected here; subtract comparisons (`cmp a,b`) and result flags (`test
/// r,r`) are lowered directly as before.
fn uses_unsupported_flags(func: &IrFunction) -> bool {
    use kamy_core::ir::{IrOp, IrTerminator};
    let mut used = HashSet::new();
    for b in &func.blocks {
        for i in &b.insts {
            used.extend(i.args.iter().copied());
        }
        for p in &b.phis {
            used.extend(p.args.iter().map(|(_, v)| *v));
        }
        if let IrTerminator::Branch { cond, .. } = &b.term {
            used.insert(*cond);
        }
    }
    let is_const = |vid: kamy_core::ir::ValueId| -> bool {
        func.blocks.iter().any(|b| {
            b.insts
                .iter()
                .any(|i| i.dest == Some(vid) && matches!(i.op, IrOp::Const(_)))
        })
    };
    func.blocks.iter().any(|b| {
        b.insts.iter().any(|i| {
            matches!(i.op, IrOp::CarryShl | IrOp::CarryShr | IrOp::CarrySar)
                && !is_const(i.args[1])
                && i.dest.is_some_and(|d| used.contains(&d))
        })
    })
}

/// True if the function reads or writes its caller's stack frame: a load/store
/// at a non-negative offset from the entry RSP (the shadow-space home slots or
/// an incoming stack argument). Stack offsets propagate from the entry RSP — an
/// `Undef` in the lifter's RSP chain, offset 0 — through the `Copy`/`Add`/`Sub`
/// (by a constant) chain and matching phis that thread the stack pointer and
/// frame pointer. Used to reject such functions (D22) because the generated
/// callee-saved prologue shifts RSP out from under those accesses.
fn accesses_caller_frame(func: &IrFunction, rsp_chain: &HashSet<kamy_core::ir::ValueId>) -> bool {
    use kamy_core::ir::{IrOp, ValueId};

    let mut consts: HashMap<ValueId, i64> = HashMap::new();
    for b in &func.blocks {
        for i in &b.insts {
            if let (Some(d), IrOp::Const(c)) = (i.dest, &i.op) {
                consts.insert(d, *c as i64);
            }
        }
    }

    let mut off: HashMap<ValueId, i64> = HashMap::new();
    for b in &func.blocks {
        for i in &b.insts {
            if let Some(d) = i.dest {
                if matches!(i.op, IrOp::Undef) && rsp_chain.contains(&d) {
                    off.insert(d, 0);
                }
            }
        }
    }
    loop {
        let mut changed = false;
        for b in &func.blocks {
            for p in &b.phis {
                if off.contains_key(&p.dest) {
                    continue;
                }
                let offs: Option<Vec<i64>> =
                    p.args.iter().map(|(_, v)| off.get(v).copied()).collect();
                if let Some(os) = offs {
                    if let Some(&first) = os.first() {
                        if os.iter().all(|&o| o == first) {
                            off.insert(p.dest, first);
                            changed = true;
                        }
                    }
                }
            }
            for i in &b.insts {
                let Some(d) = i.dest else { continue };
                if off.contains_key(&d) {
                    continue;
                }
                let new = match &i.op {
                    IrOp::Copy => i.args.first().and_then(|a| off.get(a).copied()),
                    IrOp::Add if i.args.len() == 2 => off
                        .get(&i.args[0])
                        .zip(consts.get(&i.args[1]))
                        .map(|(o, c)| o + c)
                        .or_else(|| {
                            off.get(&i.args[1])
                                .zip(consts.get(&i.args[0]))
                                .map(|(o, c)| o + c)
                        }),
                    IrOp::Sub if i.args.len() == 2 => off
                        .get(&i.args[0])
                        .zip(consts.get(&i.args[1]))
                        .map(|(o, c)| o - c),
                    _ => None,
                };
                if let Some(v) = new {
                    off.insert(d, v);
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }

    func.blocks.iter().any(|b| {
        b.insts.iter().any(|i| {
            matches!(i.op, IrOp::Load | IrOp::Store)
                && i.args
                    .first()
                    .and_then(|a| off.get(a))
                    .is_some_and(|&o| o >= 0)
        })
    })
}

#[allow(dead_code)]
fn gpr_to_iced(g: kamy_core::ir::Gpr) -> iced_x86::Register {
    use kamy_core::ir::Gpr::*;
    match g {
        Rax => iced_x86::Register::RAX,
        Rcx => iced_x86::Register::RCX,
        Rdx => iced_x86::Register::RDX,
        Rbx => iced_x86::Register::RBX,
        Rsp => iced_x86::Register::RSP,
        Rbp => iced_x86::Register::RBP,
        Rsi => iced_x86::Register::RSI,
        Rdi => iced_x86::Register::RDI,
        R8 => iced_x86::Register::R8,
        R9 => iced_x86::Register::R9,
        R10 => iced_x86::Register::R10,
        R11 => iced_x86::Register::R11,
        R12 => iced_x86::Register::R12,
        R13 => iced_x86::Register::R13,
        R14 => iced_x86::Register::R14,
        R15 => iced_x86::Register::R15,
    }
}

fn protect_inner(
    pe: &PeFile,
    module: &Module,
    functions: &[Function],
    opts: &Options,
    mut produce_body: impl FnMut(
        &Module,
        &Function,
        u64,
        u32,
    ) -> anyhow::Result<(
        Vec<u8>,
        Result<PrologueShape, Option<RejectionReason>>,
    )>,
) -> anyhow::Result<(Vec<u8>, Report)> {
    let base = module.image_base;
    let code_rva = pe.next_section_rva().get();
    let runtime_fns = pe.runtime_functions();
    let import_slots: std::collections::HashSet<u32> =
        pe.import_slots().iter().map(|r| r.get()).collect();
    let funcs_by_entry: HashMap<u32, &Function> =
        functions.iter().map(|f| (f.entry.get(), f)).collect();
    let eh_runtime = eh_runtime_functions(module, &runtime_fns, &funcs_by_entry);

    let mut report = Report {
        moved: Vec::new(),
        rejected: Vec::new(),
        ssa_lowered: 0,
    };
    let mut code: Vec<u8> = Vec::new();
    let mut moved: Vec<Moved> = Vec::new();
    let mut pending_patches: Vec<BytePatch> = Vec::new();

    let mut ordered: Vec<&Function> = functions.iter().collect();
    ordered.sort_by_key(|f| f.entry.get());
    for func in ordered {
        let _s = tracing::debug_span!("function", addr = %func.entry).entered();
        match classify(module, func, &runtime_fns, &import_slots, &eh_runtime) {
            Ok(cand) => {
                pad_to_align(&mut code, FUNCTION_ALIGN);
                let new_rva = code_rva + code.len() as u32;

                let (body, shape) = match produce_body(module, func, base, new_rva) {
                    Ok(b) => b,
                    Err(_) => {
                        report
                            .rejected
                            .push((func.entry, RejectionReason::CodegenFailure));
                        tracing::debug!(
                            addr = %func.entry,
                            reason = %RejectionReason::CodegenFailure,
                            "function rejected"
                        );
                        continue;
                    }
                };

                match &shape {
                    Ok(_) => report.ssa_lowered += 1,
                    Err(Some(reason)) => {
                        report.rejected.push((cand.entry, *reason));
                        continue;
                    }
                    Err(None) => {}
                }

                let patch = entry_patch(base, cand.entry.get(), new_rva, cand.endbr);
                let thunk_len = patch.len() as u32;
                code.extend_from_slice(&body);

                let mut patches = vec![BytePatch {
                    rva: cand.entry,
                    bytes: patch,
                }];
                let scrub_start = cand.entry.get() + thunk_len;
                if cand.end > scrub_start {
                    patches.push(BytePatch {
                        rva: Rva::new(scrub_start),
                        bytes: vec![INT3; (cand.end - scrub_start) as usize],
                    });
                }
                report.moved.push(cand.entry);
                // SSA-lowered funcs get FRESH UNWIND_INFO for the generated
                // push/align prologue (null blob when no reg was pushed);
                // relocation-shipped funcs keep their original UNWIND_INFO RVA.
                let unwind = shape
                    .ok()
                    .map(|s| kamy_pe::build_unwind_info(&s.pushed, s.stack_alloc));
                moved.push(Moved {
                    entry: cand.entry,
                    new_rva,
                    new_len: body.len() as u32,
                    unwind,
                });
                pending_patches.extend(patches);
                tracing::debug!(
                    addr = %func.entry,
                    new_rva = format_args!("{new_rva:#x}"),
                    len = body.len() as u32,
                    "moved function"
                );
            }
            Err(Some(reason)) => {
                tracing::debug!(addr = %func.entry, reason = %reason, "function rejected");
                report.rejected.push((func.entry, reason));
            }
            Err(None) => {}
        }
    }
    tracing::info!(
        ssa_lowered = report.ssa_lowered,
        rejected = report.rejected.len(),
        relocated = report.moved.len(),
        "protection complete"
    );

    if moved.is_empty() {
        return Ok((
            pe.rebuild(&PeEdits::default()).context("rebuilding PE")?,
            report,
        ));
    }

    let code_len = code.len() as u32;
    let mut new_sections: Vec<NewSection> = Vec::new();
    new_sections.push(NewSection {
        name: opts.code_section.clone(),
        rva: Rva::new(code_rva),
        flags: SectionFlags {
            read: true,
            write: false,
            execute: true,
        },
        data: code,
    });
    // Section order after code: .kamyxd (UNWIND_INFO blobs) then .pdata, so the
    // DWORD-aligned blobs sit between the code and the exception table.
    let mut xdata: Vec<u8> = Vec::new();
    let mut unwind_offsets: BTreeMap<u32, u32> = BTreeMap::new();
    for m in &moved {
        if let Some(blob) = &m.unwind {
            unwind_offsets.insert(m.entry.get(), xdata.len() as u32);
            xdata.extend_from_slice(blob);
        }
    }
    let xdata_rva = align_up(code_rva + code_len, pe.section_alignment());
    if !xdata.is_empty() {
        new_sections.push(NewSection {
            name: opts.xdata_section.clone(),
            rva: Rva::new(xdata_rva),
            flags: SectionFlags {
                read: true,
                write: false,
                execute: false,
            },
            data: xdata.clone(),
        });
    }

    let mut directories = Vec::new();

    if !runtime_fns.is_empty() {
        let moved_by_entry: HashMap<u32, &Moved> =
            moved.iter().map(|m| (m.entry.get(), m)).collect();
        let pdata = rebuild_pdata(&runtime_fns, &moved_by_entry, xdata_rva, &unwind_offsets);
        let pdata_rva = align_up(xdata_rva + xdata.len() as u32, pe.section_alignment());
        let size = pdata.len() as u32;
        new_sections.push(NewSection {
            name: opts.pdata_section.clone(),
            rva: Rva::new(pdata_rva),
            flags: SectionFlags {
                read: true,
                write: false,
                execute: false,
            },
            data: pdata,
        });
        directories.push(DirectoryUpdate {
            index: PeFile::EXCEPTION_DIRECTORY,
            rva: Rva::new(pdata_rva),
            size,
        });
    }

    let edits = PeEdits {
        new_sections,
        patches: pending_patches,
        directories,
    };
    Ok((pe.rebuild(&edits).context("rebuilding PE")?, report))
}

struct Candidate {
    entry: Rva,
    end: u32,
    endbr: bool,
}

fn classify(
    module: &Module,
    func: &Function,
    runtime_fns: &[kamy_pe::RuntimeFunction],
    import_slots: &std::collections::HashSet<u32>,
    eh_runtime: &std::collections::HashSet<u32>,
) -> Result<Candidate, Option<RejectionReason>> {
    let entry = func.entry;
    if !module.is_executable(entry) {
        return Err(None);
    }
    // The C++ exception runtime (the __CxxFrameHandler personality and everything
    // it calls during dispatch — FindHandler, FH4::TryBlockMap4, the catch/unwind
    // helpers) must stay verbatim: relocating any of it miscompiles handler lookup
    // so a thrown exception goes unhandled and the process fast-fails. Scope-table
    // / unwind reconstruction is D31 (not built); until then leave the runtime in
    // place (D22, reject-on-ambiguity).
    if eh_runtime.contains(&entry.get()) {
        return Err(Some(RejectionReason::SehComplex));
    }
    let end = func
        .blocks
        .iter()
        .map(|b| b.end.get())
        .max()
        .unwrap_or(entry.get());
    let size = end.saturating_sub(entry.get());

    use kamy_core::Terminator::{Indirect, Unknown};
    for b in &func.blocks {
        match &b.terminator {
            // D24 layer 0: `jmp [rip+slot]` is statically resolvable, not a
            // computed branch. An IAT slot is an import/forwarder thunk — never
            // a protection target, so skip it. Any other in-image slot is a
            // recoverable tail-call pending direct-ification.
            Indirect { slot: Some(s) } => {
                if import_slots.contains(&s.get()) {
                    return Err(None);
                }
                return Err(Some(RejectionReason::ResolvableIndirect));
            }
            Indirect { slot: None } => return Err(Some(RejectionReason::BadIndirectBranch)),
            Unknown => return Err(Some(RejectionReason::LiftFailure)),
            _ => {}
        }
    }

    if reloc_in_range(module, entry.get(), end) {
        return Err(Some(RejectionReason::SymbolizationUncertain));
    }

    let frags: Vec<_> = runtime_fns
        .iter()
        .filter(|r| r.begin.get() >= entry.get() && r.begin.get() < end)
        .collect();
    if frags.len() > 1 {
        return Err(Some(RejectionReason::SehComplex));
    }
    if let Some(rf) = frags.first() {
        if rf.begin != entry || unwind_flags(module, rf.unwind) != 0 {
            return Err(Some(RejectionReason::SehComplex));
        }
    }

    let endbr = module
        .bytes_at(entry)
        .is_some_and(|b| b.len() >= ENDBR64.len() && b[..ENDBR64.len()] == ENDBR64);
    let thunk_total = if endbr { ENDBR64.len() as u32 } else { 0 } + NEAR_JMP_LEN;
    if size < thunk_total {
        return Err(Some(RejectionReason::NoThunkSpace));
    }

    Ok(Candidate { entry, end, endbr })
}

fn entry_patch(base: u64, entry: u32, new_rva: u32, endbr: bool) -> Vec<u8> {
    let prefix_len = if endbr { ENDBR64.len() as u32 } else { 0 };
    let site = base + u64::from(entry) + u64::from(prefix_len);
    let target = base + u64::from(new_rva);
    let mut bytes = Vec::new();
    if endbr {
        bytes.extend_from_slice(&ENDBR64);
    }
    bytes.extend_from_slice(&thunk(site, target));
    bytes
}

fn rebuild_pdata(
    runtime_fns: &[kamy_pe::RuntimeFunction],
    moved: &HashMap<u32, &Moved>,
    xdata_rva: u32,
    unwind_offsets: &BTreeMap<u32, u32>,
) -> Vec<u8> {
    let original_begins: HashSet<u32> = runtime_fns.iter().map(|rf| rf.begin.get()).collect();
    let mut entries: Vec<(u32, u32, u32)> = runtime_fns
        .iter()
        .map(|rf| match moved.get(&rf.begin.get()) {
            // SSA-lowered: point at the fresh blob; relocation-shipped
            // (no offset recorded): keep the original UNWIND_INFO RVA.
            Some(m) => {
                let unwind = match unwind_offsets.get(&m.entry.get()) {
                    Some(off) => xdata_rva + off,
                    None => rf.unwind.get(),
                };
                (m.new_rva, m.new_rva + m.new_len, unwind)
            }
            None => (rf.begin.get(), rf.end.get(), rf.unwind.get()),
        })
        .collect();

    // SSA-moved funcs with no original runtime_function need a fresh entry.
    for (&entry, &off) in unwind_offsets {
        if original_begins.contains(&entry) {
            continue;
        }
        let m = moved[&entry];
        entries.push((m.new_rva, m.new_rva + m.new_len, xdata_rva + off));
    }

    entries.sort_by_key(|&(begin, _, _)| begin);

    let mut out = Vec::with_capacity(entries.len() * 12);
    for (begin, end, unwind) in entries {
        out.extend_from_slice(&begin.to_le_bytes());
        out.extend_from_slice(&end.to_le_bytes());
        out.extend_from_slice(&unwind.to_le_bytes());
    }
    out
}

fn reloc_in_range(module: &Module, start: u32, end: u32) -> bool {
    module
        .relocations
        .iter()
        .any(|r| r.rva.get() >= start && r.rva.get() < end)
}

/// UNWIND_INFO exception-handler RVA, or `None` when the record carries no
/// language handler. Layout: `[ver|flags, prolog, codes, frame]` then
/// `codes`-slot unwind array (padded to an even slot count), then — iff
/// `UNW_FLAG_EHANDLER|UHANDLER` — the 4-byte handler RVA.
fn unwind_handler_rva(module: &Module, unwind: Rva) -> Option<u32> {
    let b = module.bytes_at(unwind)?;
    let flags = b.first()? >> 3;
    if flags & 0x3 == 0 {
        return None;
    }
    let count = *b.get(2)? as usize;
    let off = 4 + ((count + 1) & !1) * 2;
    let slice = b.get(off..off + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// Functions that must stay verbatim because the module dispatches C++ exceptions
/// through them: the `__CxxFrameHandler` personality cluster — the personality and
/// everything it reaches by a direct `call`/`jmp` or an address-taken function
/// pointer (its catch funnels and continuation helpers are guard-dispatched
/// indirectly, so a direct-call walk alone misses them). Relocating any of it
/// miscompiles handler lookup so a throw goes unhandled and the process
/// fast-fails (scope-table / unwind reconstruction is D31, not built).
///
/// The set is empty unless some *user* function (one outside the runtime cluster)
/// actually names a C++ personality as its unwind handler — i.e. the image has a
/// real `try`/`catch`. SEH-only, `/GS`-only and exception-free images (whose
/// static CRT still contains the dormant runtime) keep moving everything, so their
/// coverage is untouched. A personality is taken to be C++ when its reachable
/// cluster is non-trivial; the small `__C_specific_handler` / `__GSHandlerCheck`
/// clusters stay movable.
fn eh_runtime_functions(
    module: &Module,
    runtime_fns: &[kamy_pe::RuntimeFunction],
    funcs_by_entry: &HashMap<u32, &Function>,
) -> std::collections::HashSet<u32> {
    use std::collections::HashSet;
    let base = module.image_base;
    let reach = |seed: u32| -> HashSet<u32> {
        let mut reached = HashSet::new();
        let mut stack = vec![seed];
        while let Some(rva) = stack.pop() {
            if !reached.insert(rva) {
                continue;
            }
            let Some(func) = funcs_by_entry.get(&rva) else {
                continue;
            };
            for insn in function_instructions(module, func) {
                let mut follow = |target: u64| {
                    if target >= base {
                        let t = (target - base) as u32;
                        if funcs_by_entry.contains_key(&t) && !reached.contains(&t) {
                            stack.push(t);
                        }
                    }
                };
                if insn.is_call_near() || insn.is_jmp_short_or_near() {
                    follow(insn.near_branch_target());
                }
                if insn.is_ip_rel_memory_operand() {
                    follow(insn.memory_displacement64());
                }
            }
        }
        reached
    };

    // The C++ personality's cluster is the whole FH3/FH4 dispatch runtime; the
    // __C_specific_handler / __GSHandlerCheck clusters are one or two helpers.
    const CXX_CLUSTER_MIN: usize = 4;
    let personalities: HashSet<u32> = runtime_fns
        .iter()
        .filter_map(|rf| unwind_handler_rva(module, rf.unwind))
        .filter(|h| funcs_by_entry.contains_key(h))
        .collect();

    let mut cxx_personalities: HashSet<u32> = HashSet::new();
    let mut runtime: HashSet<u32> = HashSet::new();
    for &p in &personalities {
        let cluster = reach(p);
        if cluster.len() >= CXX_CLUSTER_MIN {
            cxx_personalities.insert(p);
            runtime.extend(cluster);
        }
    }

    // Only leave the runtime verbatim when real user code dispatches through it —
    // a function with a C++ personality handler that is not itself the runtime.
    let user_dispatches = runtime_fns.iter().any(|rf| {
        unwind_handler_rva(module, rf.unwind).is_some_and(|h| cxx_personalities.contains(&h))
            && !runtime.contains(&rf.begin.get())
    });
    if user_dispatches {
        runtime
    } else {
        HashSet::new()
    }
}

fn unwind_flags(module: &Module, unwind: Rva) -> u8 {
    module
        .bytes_at(unwind)
        .and_then(|b| b.first())
        .map_or(0xff, |b| b >> 3)
}

fn align_up(value: u32, align: u32) -> u32 {
    if align == 0 {
        return value;
    }
    value.div_ceil(align) * align
}

fn pad_to_align(buf: &mut Vec<u8>, align: u32) {
    let rem = buf.len() % align as usize;
    if rem != 0 {
        buf.extend(std::iter::repeat_n(INT3, align as usize - rem));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rebuild_pdata_appends_entry_for_ssa_moved_leaf() {
        let entry = 0x1000u32;
        let m = Moved {
            entry: Rva::new(entry),
            new_rva: 0x5000,
            new_len: 0x40,
            unwind: Some(vec![0x01, 0, 0, 0]),
        };
        let mut moved: HashMap<u32, &Moved> = HashMap::new();
        moved.insert(entry, &m);
        let mut unwind_offsets: BTreeMap<u32, u32> = BTreeMap::new();
        unwind_offsets.insert(entry, 0x8);
        let xdata_rva = 0x9000u32;

        let out = rebuild_pdata(&[], &moved, xdata_rva, &unwind_offsets);
        assert_eq!(out.len(), 12);
        let begin = u32::from_le_bytes(out[0..4].try_into().unwrap());
        let end = u32::from_le_bytes(out[4..8].try_into().unwrap());
        let unwind = u32::from_le_bytes(out[8..12].try_into().unwrap());
        assert_eq!(begin, 0x5000);
        assert_eq!(end, 0x5040);
        assert_eq!(unwind, xdata_rva + 0x8);
    }
}
