//! Reference-rewriting linker with conservative residency and native PE output.

mod rewrite;
mod translation;

use anyhow::{Context, ensure};
use iced_x86::{Instruction, Register};
use kamy_codegen::relocate;
use kamy_core::ir::{CallingConvLookup, IrFunction, MapCallConv, win64_import_signature};
use kamy_core::{Function, Module, RejectionReason, Rva, SectionFlags, SymbolKind, Terminator};
use kamy_disasm::function_instructions;
use kamy_pe::{BytePatch, DirectoryUpdate, NewSection, PeEdits, PeFile};
use std::collections::{BTreeMap, HashMap, HashSet};

const FUNCTION_ALIGN: u32 = 16;

pub struct Options {
    pub code_section: String,
    pub pdata_section: String,
    pub xdata_section: String,
    pub selector: Option<kamy_core::FunctionSelector>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            code_section: ".kamy".into(),
            pdata_section: ".kamypd".into(),
            xdata_section: ".kamyxd".into(),
            selector: None,
        }
    }
}

pub struct Report {
    pub moved: Vec<Rva>,
    pub rejected: Vec<(Rva, RejectionReason)>,
    pub ssa_lowered: usize,
    pub ssa_lowered_rvas: Vec<Rva>,
    pub address_map: BTreeMap<Rva, Rva>,
}

struct Prepared<'a> {
    function: &'a Function,
    instructions: Vec<Instruction>,
    references: Vec<Operand>,
    indirect: Vec<(usize, Register)>,
    slot_len: u32,
    new_rva: Option<u32>,
    body: Vec<u8>,
    unwind: Vec<kamy_seh::UnwindRange>,
}

enum Operand {
    Branch(usize, u64),
    Rip(usize, u64),
}

struct EncodedHelper {
    rva: u32,
    body: Vec<u8>,
    unwind: Vec<kamy_seh::UnwindRange>,
}

/// Resolve every call target we can narrow to a precise Win64 signature, keyed
/// by target VA for [`MapCallConv`]. Three sources, lowest precedence first:
/// callee-side argument inference on the target's own functions (keyed by entry
/// VA), then import slots (`call [rip+slot]`, keyed by slot VA) and single-block
/// import thunks (`jmp [rip+slot]`, keyed by thunk entry VA) — the named-import
/// signatures are authoritative and overwrite an inferred entry at the same VA.
/// Everything else falls back to the Win64 default at the call site.
pub fn build_callconv(module: &Module) -> MapCallConv {
    let base = module.image_base;
    let mut slot_name: HashMap<u32, &str> = HashMap::new();
    for s in &module.symbols {
        if s.kind == SymbolKind::Import {
            slot_name.insert(s.rva.get(), s.name.as_str());
        }
    }

    let mut by_va: HashMap<u64, kamy_core::ir::FnSignature> = HashMap::new();
    for func in &module.functions {
        if let Some(sig) = kamy_analysis::infer_signature(module, func) {
            // A full four-argument result is the default already; only a genuine
            // narrowing is worth an entry.
            if sig.args.len() < 4 {
                by_va.insert(base + u64::from(func.entry.get()), sig);
            }
        }
    }
    for (&slot_rva, name) in &slot_name {
        if let Some(sig) = win64_import_signature(name) {
            by_va.insert(base + u64::from(slot_rva), sig);
        }
    }
    for func in &module.functions {
        if func.blocks.len() != 1 {
            continue;
        }
        let Terminator::Indirect { slot: Some(slot) } = func.blocks[0].terminator else {
            continue;
        };
        if let Some(name) = slot_name.get(&slot.get()) {
            if let Some(sig) = win64_import_signature(name) {
                by_va.insert(base + u64::from(func.entry.get()), sig);
            }
        }
    }

    MapCallConv::new(by_va)
}

/// Functions that cannot be transformed or safely referenced remain resident.
pub fn protect_with_transforms(
    pe: &PeFile,
    module: &Module,
    functions: &[Function],
    opts: &Options,
    cc: &dyn CallingConvLookup,
    transform: &mut dyn FnMut(Rva, &mut IrFunction, f32),
) -> anyhow::Result<(Vec<u8>, Report)> {
    protect_inner(pe, module, functions, opts, cc, transform)
}

fn ssa_instructions(
    module: &Module,
    func: &Function,
    cc: &dyn CallingConvLookup,
    transform: &mut dyn FnMut(Rva, &mut IrFunction, f32),
) -> Result<Vec<Instruction>, RejectionReason> {
    // Only pressure retries re-lift: each transform intensity needs clean SSA.
    const INTENSITY_LADDER: [f32; 4] = [1.0, 0.5, 0.25, 0.0];
    let base = module.image_base;
    let entry_va = base
        .checked_add(u64::from(func.entry.get()))
        .ok_or(RejectionReason::InvalidReference)?;
    for block in &func.blocks {
        let len = block
            .end
            .get()
            .checked_sub(block.start.get())
            .ok_or(RejectionReason::LiftFailure)? as usize;
        let bytes = module
            .bytes_at(block.start)
            .and_then(|bytes| bytes.get(..len))
            .ok_or(RejectionReason::LiftFailure)?;
        let ip = base
            .checked_add(u64::from(block.start.get()))
            .ok_or(RejectionReason::InvalidReference)?;
        let mut decoder = iced_x86::Decoder::with_ip(64, bytes, ip, iced_x86::DecoderOptions::NONE);
        while decoder.can_decode() {
            // EIP-relative lowering currently loses address provenance in the lifter.
            if decoder.decode().memory_base() == Register::EIP {
                return Err(RejectionReason::UnsupportedInstruction);
            }
        }
    }
    for (i, &intensity) in INTENSITY_LADDER.iter().enumerate() {
        let mut result = kamy_lift::lift_function(module, func, cc);
        if result.unsupported {
            return Err(RejectionReason::UnsupportedInstruction);
        }
        kamy_lift::ssa::construct_ssa(&mut result);
        transform(func.entry, &mut result.func, intensity);
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
                    entry_va,
                    &used,
                    &used_xmm,
                );
                return Ok(instrs);
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

/// Variable-count shift flags cannot be reconstructed without the original CL.
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
///
/// Also true for a /GS stack-cookie function (#23): the cookie is framed by
/// xoring the live stack pointer into it (`xor rax, rsp`), which no ordinary
/// code does. The generated prologue shifts RSP, so the epilogue's
/// `__security_check_cookie` fast-fails (0xC0000409); reject instead.
fn accesses_caller_frame(func: &IrFunction, rsp_chain: &HashSet<kamy_core::ir::ValueId>) -> bool {
    use kamy_core::ir::{IrOp, ValueId};
    if func.blocks.iter().any(|b| {
        b.insts
            .iter()
            .any(|i| matches!(i.op, IrOp::Xor) && i.args.iter().any(|a| rsp_chain.contains(a)))
    }) {
        return true;
    }

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

impl Prepared<'_> {
    fn bind(
        &mut self,
        addresses: &BTreeMap<u64, u64>,
        helpers: &BTreeMap<u32, (Register, u32)>,
        base: u64,
    ) -> anyhow::Result<bool> {
        let mut changed = false;
        for reference in &self.references {
            match *reference {
                Operand::Branch(index, original) => {
                    let target = addresses.get(&original).copied().unwrap_or(original);
                    changed |= self.instructions[index].near_branch_target() != target;
                }
                Operand::Rip(index, original) => {
                    let target = addresses.get(&original).copied().unwrap_or(original);
                    changed |= self.instructions[index].ip_rel_memory_address() != target;
                }
            }
        }
        for &(index, register) in &self.indirect {
            let (_, rva) = helpers
                .get(&(register as u32))
                .context("missing indirect translator")?;
            let target = base
                .checked_add(u64::from(*rva))
                .context("translator VA overflow")?;
            changed |= self.instructions[index].near_branch_target() != target;
        }
        if !changed {
            return Ok(false);
        }
        for reference in &self.references {
            match *reference {
                Operand::Branch(index, original) => {
                    self.instructions[index].set_near_branch64(original)
                }
                Operand::Rip(index, original) => {
                    self.instructions[index].set_memory_displacement64(original)
                }
            }
        }
        kamy_codegen::rebase_instructions(&mut self.instructions, addresses)?;
        for &(index, register) in &self.indirect {
            let rva = helpers[&(register as u32)].1;
            self.instructions[index].set_near_branch64(
                base.checked_add(u64::from(rva))
                    .context("translator VA overflow")?,
            );
        }
        Ok(changed)
    }
}

fn protect_inner(
    pe: &PeFile,
    module: &Module,
    functions: &[Function],
    opts: &Options,
    cc: &dyn CallingConvLookup,
    transform: &mut dyn FnMut(Rva, &mut IrFunction, f32),
) -> anyhow::Result<(Vec<u8>, Report)> {
    let metadata = pe
        .metadata_references()
        .context("enumerating image references")?;
    let reference_model = kamy_analysis::build_reference_model(module, &metadata)
        .context("building reference model")?;
    let base = module.image_base;
    let image_end = module.sections.iter().try_fold(0u32, |end, section| {
        section
            .rva
            .get()
            .checked_add(section.virtual_size)
            .map(|next| end.max(next))
            .context("original section RVA overflow")
    })?;
    let code_rva = align_up(image_end, pe.section_alignment())?;
    let code_va = base
        .checked_add(u64::from(code_rva))
        .context("code VA overflow")?;
    let runtime_fns = pe.runtime_functions();
    let import_slots = pe.import_slots().iter().map(|r| r.get()).collect();
    let funcs_by_entry = functions.iter().map(|f| (f.entry.get(), f)).collect();
    let eh_runtime = eh_runtime_functions(module, &runtime_fns, &funcs_by_entry);
    let has_cfg = pe.has_cfg();
    let cfg_usable = !has_cfg || pe.cfg_edits(Rva::new(code_rva), Rva::new(code_rva)).is_ok();
    let has_cfg_check = has_cfg && pe.has_cfg_check();
    let mut report = Report {
        moved: Vec::new(),
        rejected: Vec::new(),
        ssa_lowered: 0,
        ssa_lowered_rvas: Vec::new(),
        address_map: BTreeMap::new(),
    };
    let mut ordered: Vec<_> = functions.iter().collect();
    ordered.sort_by_key(|function| function.entry);
    let mut prepared = Vec::new();
    for function in ordered {
        match classify(module, function, &runtime_fns, &import_slots, &eh_runtime) {
            Ok(()) => {}
            Err(Some(reason)) => {
                report.rejected.push((function.entry, reason));
                continue;
            }
            Err(None) => continue,
        }
        let reason = if pe.subsystem() == 1 && module.entry_point == Some(function.entry) {
            Some(RejectionReason::InvalidReference)
        } else if opts
            .selector
            .as_ref()
            .is_some_and(|selector| !selector.allows(function.entry))
        {
            Some(RejectionReason::Deselected)
        } else if !reference_model.is_resolved(function.entry) {
            Some(RejectionReason::SymbolizationUncertain)
        } else if !cfg_usable {
            Some(RejectionReason::InvalidReference)
        } else {
            None
        };
        if let Some(reason) = reason {
            report.rejected.push((function.entry, reason));
            continue;
        }
        let mut instructions = match ssa_instructions(module, function, cc, transform) {
            Ok(instructions) => instructions,
            Err(reason) => {
                report.rejected.push((function.entry, reason));
                continue;
            }
        };
        let indirect = match translation::instrument(&mut instructions) {
            Ok(indirect) => indirect,
            Err(_) => {
                report
                    .rejected
                    .push((function.entry, RejectionReason::InvalidReference));
                continue;
            }
        };
        let labels: HashSet<_> = instructions
            .iter()
            .map(Instruction::ip)
            .filter(|ip| *ip != 0)
            .collect();
        let indirect_indices: HashSet<_> = indirect.iter().map(|(index, _)| *index).collect();
        let mut references = Vec::new();
        for (index, instruction) in instructions.iter().enumerate() {
            if !indirect_indices.contains(&index)
                && matches!(instruction.op0_kind(), iced_x86::OpKind::NearBranch64)
                && !labels.contains(&instruction.near_branch_target())
            {
                references.push(Operand::Branch(index, instruction.near_branch_target()));
            }
            if instruction.is_ip_rel_memory_operand()
                && !labels.contains(&instruction.ip_rel_memory_address())
            {
                references.push(Operand::Rip(index, instruction.ip_rel_memory_address()));
            }
        }
        prepared.push(Prepared {
            function,
            instructions,
            references,
            indirect,
            slot_len: 0,
            new_rva: None,
            body: Vec::new(),
            unwind: Vec::new(),
        });
    }

    let seed_addresses = prepared
        .iter()
        .map(|function| {
            Ok((
                base.checked_add(u64::from(function.function.entry.get()))
                    .context("original VA overflow")?,
                code_va,
            ))
        })
        .collect::<anyhow::Result<BTreeMap<_, _>>>()?;
    let seed_helpers = prepared
        .iter()
        .flat_map(|function| function.indirect.iter())
        .map(|&(_, register)| (register as u32, (register, code_rva)))
        .collect();
    prepared.retain_mut(|function| {
        let result = function
            .bind(&seed_addresses, &seed_helpers, base)
            .and_then(|_| relocate(&function.instructions, code_va))
            .and_then(|body| {
                ensure!(!body.is_empty(), "empty selected function");
                u32::try_from(body.len()).context("encoded function exceeds RVA space")
            });
        match result {
            Ok(len) => {
                function.slot_len = len;
                true
            }
            Err(_) => {
                report
                    .rejected
                    .push((function.function.entry, RejectionReason::CodegenFailure));
                false
            }
        }
    });

    let (
        addresses,
        helpers,
        encoded_helpers,
        check_rva,
        check_unwind,
        code_end,
        xdata_rva,
        mut patches,
        mut reference_edits,
    ) = loop {
        if prepared.is_empty() {
            report.rejected.sort_by_key(|&(entry, _)| entry);
            return Ok((
                pe.rebuild(&PeEdits::default()).context("rebuilding PE")?,
                report,
            ));
        }
        let mut cursor = code_rva;
        let mut addresses = BTreeMap::new();
        for function in &prepared {
            cursor = align_up(cursor, FUNCTION_ALIGN)?;
            addresses.insert(function.function.entry, Rva::new(cursor));
            cursor = cursor
                .checked_add(function.slot_len)
                .context("code layout RVA overflow")?;
        }
        let (patches, pinned) = rewrite::resident_patches(module, &reference_model, &addresses);
        if !pinned.is_empty() {
            prepared.retain(|function| {
                if pinned.contains(&function.function.entry) {
                    report
                        .rejected
                        .push((function.function.entry, RejectionReason::InvalidReference));
                    false
                } else {
                    true
                }
            });
            continue;
        }
        let mut helpers = BTreeMap::new();
        for function in &prepared {
            for &(_, register) in &function.indirect {
                helpers.insert(register as u32, (register, 0));
            }
        }
        if has_cfg {
            helpers.insert(Register::RAX as u32, (Register::RAX, 0));
        }
        for (_, rva) in helpers.values_mut() {
            cursor = align_up(cursor, FUNCTION_ALIGN)?;
            *rva = cursor;
            cursor = cursor
                .checked_add(translation::HELPER_LEN)
                .context("helper RVA overflow")?;
        }
        let check_rva = if has_cfg_check {
            cursor = align_up(cursor, FUNCTION_ALIGN)?;
            let rva = cursor;
            cursor = cursor
                .checked_add(translation::CHECK_BYTES.len() as u32)
                .context("CFG helper RVA overflow")?;
            Some(rva)
        } else {
            None
        };
        let va_addresses = addresses
            .iter()
            .map(|(&old, &new)| {
                Ok((
                    base.checked_add(u64::from(old.get()))
                        .context("original VA overflow")?,
                    base.checked_add(u64::from(new.get()))
                        .context("new VA overflow")?,
                ))
            })
            .collect::<anyhow::Result<BTreeMap<_, _>>>()?;
        let mut rejected = BTreeMap::new();
        let mut grew = false;
        for function in &mut prepared {
            let new_rva = addresses[&function.function.entry].get();
            let bindings_changed = match function.bind(&va_addresses, &helpers, base) {
                Ok(changed) => changed,
                Err(_) => {
                    rejected.insert(function.function.entry, RejectionReason::InvalidReference);
                    continue;
                }
            };
            if function.new_rva == Some(new_rva) && !bindings_changed {
                continue;
            }
            let new_va = base
                .checked_add(u64::from(new_rva))
                .context("new VA overflow")?;
            let body = match relocate(&function.instructions, new_va) {
                Ok(body) => body,
                Err(_) => {
                    rejected.insert(function.function.entry, RejectionReason::CodegenFailure);
                    continue;
                }
            };
            let len = u32::try_from(body.len()).context("encoded function exceeds RVA space")?;
            if len > function.slot_len {
                // Slots grow monotonically; branch widening cannot oscillate layout.
                function.slot_len = len;
                grew = true;
            }
            function.new_rva = Some(new_rva);
            function.body = body;
            function.unwind.clear();
        }
        if !rejected.is_empty() {
            prepared.retain(|function| !rejected.contains_key(&function.function.entry));
            report.rejected.extend(rejected);
            continue;
        }
        if grew {
            continue;
        }
        // Widening can put a tentative successor entry inside the current body.
        for function in &mut prepared {
            if !function.unwind.is_empty() {
                continue;
            }
            let new_va = base
                .checked_add(u64::from(addresses[&function.function.entry].get()))
                .context("new VA overflow")?;
            match kamy_seh::unwind_ranges(&function.body, new_va) {
                Ok(ranges) if !ranges.is_empty() => function.unwind = ranges,
                _ => {
                    rejected.insert(function.function.entry, RejectionReason::EhNoBucketCreation);
                }
            }
        }
        if !rejected.is_empty() {
            prepared.retain(|function| !rejected.contains_key(&function.function.entry));
            report.rejected.extend(rejected);
            continue;
        }
        let reference_edits = match pe.rebase_references(&addresses) {
            Ok(edits) => edits,
            Err(error) => {
                let mut pinned = HashSet::new();
                for (&old, &new) in &addresses {
                    if pe.rebase_references(&BTreeMap::from([(old, new)])).is_err() {
                        pinned.insert(old);
                    }
                }
                if pinned.is_empty() {
                    return Err(error).context("rebasing image references");
                }
                prepared.retain(|function| {
                    if pinned.contains(&function.function.entry) {
                        report
                            .rejected
                            .push((function.function.entry, RejectionReason::InvalidReference));
                        false
                    } else {
                        true
                    }
                });
                continue;
            }
        };
        let xdata_rva = align_up(cursor, pe.section_alignment())?;
        let mut encoded_helpers = Vec::with_capacity(helpers.len());
        let mut bad_helpers = BTreeMap::new();
        for (&key, &(register, rva)) in &helpers {
            let body = match translation::helper(register, rva, xdata_rva) {
                Ok(body) => body,
                Err(_) => {
                    bad_helpers.insert(key, RejectionReason::InvalidReference);
                    continue;
                }
            };
            let va = base
                .checked_add(u64::from(rva))
                .context("helper VA overflow")?;
            match kamy_seh::unwind_ranges(&body, va) {
                Ok(unwind) if !unwind.is_empty() => {
                    encoded_helpers.push(EncodedHelper { rva, body, unwind })
                }
                _ => {
                    bad_helpers.insert(key, RejectionReason::EhNoBucketCreation);
                }
            }
        }
        let mut global_reject = if has_cfg {
            bad_helpers.get(&(Register::RAX as u32)).copied()
        } else {
            None
        };
        let check_unwind = if let Some(rva) = check_rva {
            let va = base
                .checked_add(u64::from(rva))
                .context("CFG helper VA overflow")?;
            match kamy_seh::unwind_ranges(&translation::CHECK_BYTES, va) {
                Ok(ranges) if !ranges.is_empty() => Some(ranges),
                _ => {
                    global_reject = Some(RejectionReason::EhNoBucketCreation);
                    None
                }
            }
        } else {
            None
        };
        if global_reject.is_some() || !bad_helpers.is_empty() {
            prepared.retain(|function| {
                let reason = global_reject.or_else(|| {
                    function
                        .indirect
                        .iter()
                        .find_map(|&(_, register)| bad_helpers.get(&(register as u32)).copied())
                });
                if let Some(reason) = reason {
                    report.rejected.push((function.function.entry, reason));
                    false
                } else {
                    true
                }
            });
            continue;
        }
        break (
            addresses,
            helpers,
            encoded_helpers,
            check_rva,
            check_unwind,
            cursor,
            xdata_rva,
            patches,
            reference_edits,
        );
    };

    patches.append(&mut reference_edits.patches);
    if has_cfg {
        let dispatch = helpers[&(Register::RAX as u32)].1;
        let check = check_rva.unwrap_or(dispatch);
        let (mut cfg_patches, relocations) = pe
            .cfg_edits(Rva::new(check), Rva::new(dispatch))
            .context("rewriting CFG dispatch")?;
        patches.append(&mut cfg_patches);
        reference_edits.relocations.extend(relocations);
    }
    let code_len = code_end
        .checked_sub(code_rva)
        .context("invalid code layout")? as usize;
    let mut code = Vec::with_capacity(code_len);
    let mut xdata = if helpers.is_empty() {
        Vec::new()
    } else {
        translation::table(&addresses)?
    };
    let mut entries: Vec<_> = runtime_fns
        .iter()
        .filter(|function| !addresses.contains_key(&function.begin))
        .map(|function| {
            (
                function.begin.get(),
                function.end.get(),
                function.unwind.get(),
            )
        })
        .collect();
    for function in &prepared {
        let new_rva = addresses[&function.function.entry].get();
        append_code(&mut code, code_rva, new_rva, &function.body)?;
        append_unwind(
            &mut xdata,
            &mut entries,
            xdata_rva,
            new_rva,
            u32::try_from(function.body.len()).context("function size overflow")?,
            &function.unwind,
        )?;
        for block in &function.function.blocks {
            let len = block
                .end
                .get()
                .checked_sub(block.start.get())
                .context("invalid owned block")?;
            let mut bytes = Vec::with_capacity(len as usize);
            append_nops(&mut bytes, len as usize);
            patches.push(BytePatch {
                rva: block.start,
                bytes,
            });
        }
    }
    for helper in encoded_helpers {
        append_code(&mut code, code_rva, helper.rva, &helper.body)?;
        append_unwind(
            &mut xdata,
            &mut entries,
            xdata_rva,
            helper.rva,
            translation::HELPER_LEN,
            &helper.unwind,
        )?;
    }
    if let Some(rva) = check_rva {
        let ranges = check_unwind
            .as_deref()
            .context("missing CFG check unwind state")?;
        append_code(&mut code, code_rva, rva, &translation::CHECK_BYTES)?;
        append_unwind(
            &mut xdata,
            &mut entries,
            xdata_rva,
            rva,
            translation::CHECK_BYTES.len() as u32,
            ranges,
        )?;
    }
    let reserved = code_end
        .checked_sub(code_rva)
        .context("invalid code layout")? as usize;
    ensure!(code.len() <= reserved, "code exceeded reserved layout");
    let padding = reserved - code.len();
    append_nops(&mut code, padding);
    let pdata = encode_pdata(&mut entries)?;
    let pdata_rva = align_up(
        xdata_rva
            .checked_add(u32::try_from(xdata.len()).context("xdata size overflow")?)
            .context("xdata RVA overflow")?,
        pe.section_alignment(),
    )?;
    let pdata_len = u32::try_from(pdata.len()).context("pdata size overflow")?;
    let mut new_sections = vec![
        section(opts.code_section.clone(), code_rva, true, code),
        section(opts.xdata_section.clone(), xdata_rva, false, xdata),
        section(opts.pdata_section.clone(), pdata_rva, false, pdata),
    ];
    let mut directories = vec![DirectoryUpdate {
        index: PeFile::EXCEPTION_DIRECTORY,
        rva: Rva::new(pdata_rva),
        size: pdata_len,
    }];
    let relocations = kamy_pe::encode_base_relocations(&reference_edits.relocations)
        .context("serializing base relocations")?;
    if relocations.is_empty() {
        directories.push(DirectoryUpdate {
            index: 5,
            rva: Rva::ZERO,
            size: 0,
        });
    } else {
        let reloc_rva = align_up(
            pdata_rva
                .checked_add(pdata_len)
                .context("pdata RVA overflow")?,
            pe.section_alignment(),
        )?;
        let size = u32::try_from(relocations.len()).context("relocation size overflow")?;
        new_sections.push(section(".kamyr".into(), reloc_rva, false, relocations));
        directories.push(DirectoryUpdate {
            index: 5,
            rva: Rva::new(reloc_rva),
            size,
        });
    }
    let last_section = new_sections.last().context("missing output section")?;
    let debug_rva = align_up(
        last_section
            .rva
            .get()
            .checked_add(u32::try_from(last_section.data.len()).context("section size overflow")?)
            .context("section RVA overflow")?,
        pe.section_alignment(),
    )?;
    let debug_moves = prepared
        .iter()
        .map(|function| {
            Ok((
                function.function.entry,
                addresses[&function.function.entry],
                u32::try_from(function.body.len()).context("function size overflow")?,
            ))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    if let Some((debug, directory)) = pe
        .rebuild_debug_directory(&debug_moves, Rva::new(debug_rva))
        .context("rebuilding debug directory")?
    {
        new_sections.push(section(".kamyd".into(), debug_rva, false, debug));
        directories.push(directory);
    }
    report.moved = addresses.keys().copied().collect();
    report.ssa_lowered = report.moved.len();
    report.ssa_lowered_rvas = report.moved.clone();
    report.rejected.sort_by_key(|&(entry, _)| entry);
    report.address_map = addresses;
    let edits = PeEdits {
        new_sections,
        patches,
        directories,
        entry_point: reference_edits.entry_point,
        clear_guard_cf: has_cfg,
    };
    Ok((pe.rebuild(&edits).context("rebuilding PE")?, report))
}

fn section(name: String, rva: u32, execute: bool, data: Vec<u8>) -> NewSection {
    NewSection {
        name,
        rva: Rva::new(rva),
        flags: SectionFlags {
            read: true,
            write: false,
            execute,
        },
        data,
    }
}

fn append_code(code: &mut Vec<u8>, code_rva: u32, rva: u32, body: &[u8]) -> anyhow::Result<()> {
    let offset = rva
        .checked_sub(code_rva)
        .context("code before section start")? as usize;
    ensure!(code.len() <= offset, "overlapping generated code");
    let padding = offset - code.len();
    append_nops(code, padding);
    code.extend_from_slice(body);
    Ok(())
}

fn append_unwind(
    xdata: &mut Vec<u8>,
    entries: &mut Vec<(u32, u32, u32)>,
    xdata_rva: u32,
    function_rva: u32,
    function_len: u32,
    ranges: &[kamy_seh::UnwindRange],
) -> anyhow::Result<()> {
    ensure!(!ranges.is_empty(), "no reachable unwind ranges");
    for range in ranges {
        ensure!(
            range.begin < range.end && range.end <= function_len,
            "invalid unwind range"
        );
        let padding = (4 - xdata.len() % 4) % 4;
        xdata.resize(
            xdata
                .len()
                .checked_add(padding)
                .context("xdata size overflow")?,
            0,
        );
        let unwind = xdata_rva
            .checked_add(u32::try_from(xdata.len()).context("xdata size overflow")?)
            .context("unwind RVA overflow")?;
        xdata.extend_from_slice(&range.info);
        entries.push((
            function_rva
                .checked_add(range.begin)
                .context("unwind begin overflow")?,
            function_rva
                .checked_add(range.end)
                .context("unwind end overflow")?,
            unwind,
        ));
    }
    Ok(())
}

fn encode_pdata(entries: &mut [(u32, u32, u32)]) -> anyhow::Result<Vec<u8>> {
    entries.sort_by_key(|entry| entry.0);
    for entry in entries.iter() {
        ensure!(entry.0 < entry.1, "empty runtime-function range");
    }
    for pair in entries.windows(2) {
        ensure!(
            pair[0].1 <= pair[1].0,
            "overlapping runtime-function ranges"
        );
    }
    let mut bytes = Vec::with_capacity(
        entries
            .len()
            .checked_mul(12)
            .context("pdata size overflow")?,
    );
    for &(begin, end, unwind) in entries.iter() {
        bytes.extend_from_slice(&begin.to_le_bytes());
        bytes.extend_from_slice(&end.to_le_bytes());
        bytes.extend_from_slice(&unwind.to_le_bytes());
    }
    Ok(bytes)
}

fn classify(
    module: &Module,
    func: &Function,
    runtime_fns: &[kamy_pe::RuntimeFunction],
    import_slots: &std::collections::HashSet<u32>,
    eh_runtime: &std::collections::HashSet<u32>,
) -> Result<(), Option<RejectionReason>> {
    let entry = func.entry;
    if !module.is_executable(entry) {
        return Err(None);
    }
    if func.blocks.iter().any(|block| {
        matches!(block.terminator, Terminator::Indirect { slot: Some(slot) } if import_slots.contains(&slot.get()))
    }) {
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

    use kamy_core::Terminator::{Indirect, Unknown};
    for b in &func.blocks {
        match &b.terminator {
            Indirect { slot: Some(_) } => return Err(Some(RejectionReason::ResolvableIndirect)),
            Indirect { slot: None } => return Err(Some(RejectionReason::BadIndirectBranch)),
            Unknown => return Err(Some(RejectionReason::LiftFailure)),
            _ => {}
        }
    }

    if reloc_in_range(module, entry.get(), end) {
        return Err(Some(RejectionReason::SymbolizationUncertain));
    }

    let mut frags = runtime_fns
        .iter()
        .filter(|r| r.begin.get() < end && r.end.get() > entry.get());
    let first = frags.next();
    if frags.next().is_some() {
        return Err(Some(RejectionReason::SehComplex));
    }
    if let Some(rf) = first {
        if rf.begin != entry || unwind_flags(module, rf.unwind) != 0 {
            return Err(Some(RejectionReason::SehComplex));
        }
        if rf.end.get() > end
            && module.functions.iter().any(|other| {
                other.entry != entry
                    && other
                        .blocks
                        .iter()
                        .any(|block| block.start < rf.end && block.end > rf.begin)
            })
        {
            return Err(Some(RejectionReason::EhFunctionDoesntOwnInfo));
        }
    }

    Ok(())
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

fn align_up(value: u32, align: u32) -> anyhow::Result<u32> {
    ensure!(align != 0, "zero section alignment");
    let remainder = value % align;
    if remainder == 0 {
        Ok(value)
    } else {
        value
            .checked_add(align - remainder)
            .context("aligned RVA overflow")
    }
}

fn append_nops(bytes: &mut Vec<u8>, mut len: usize) {
    const NOPS: [&[u8]; 10] = [
        &[],
        &[0x90],
        &[0x66, 0x90],
        &[0x0f, 0x1f, 0x00],
        &[0x0f, 0x1f, 0x40, 0x00],
        &[0x0f, 0x1f, 0x44, 0x00, 0x00],
        &[0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00],
        &[0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00],
        &[0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
        &[0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
    ];
    while len != 0 {
        let size = len.min(9);
        bytes.extend_from_slice(NOPS[size]);
        len -= size;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_table_includes_moved_leaf_without_original_pdata() {
        let ranges = kamy_seh::unwind_ranges(&[0xc3], 0x140005000).unwrap();
        let mut xdata = Vec::new();
        let mut entries = Vec::new();
        append_unwind(&mut xdata, &mut entries, 0x9000, 0x5000, 1, &ranges).unwrap();
        let out = encode_pdata(&mut entries).unwrap();
        assert_eq!(out.len(), 12);
        assert_eq!(u32::from_le_bytes(out[0..4].try_into().unwrap()), 0x5000);
        assert_eq!(u32::from_le_bytes(out[4..8].try_into().unwrap()), 0x5001);
        assert_eq!(u32::from_le_bytes(out[8..12].try_into().unwrap()), 0x9000);
    }

    #[test]
    fn encoded_caller_rebinds_when_callee_becomes_resident() {
        let function = Function {
            entry: Rva::new(0x1000),
            blocks: vec![],
        };
        let instructions = vec![
            Instruction::with_branch(iced_x86::Code::Call_rel32_64, 0x140002000).unwrap(),
            Instruction::with(iced_x86::Code::Retnq),
        ];
        let mut prepared = Prepared {
            function: &function,
            instructions,
            references: vec![Operand::Branch(0, 0x140002000)],
            indirect: vec![],
            slot_len: 0,
            new_rva: None,
            body: vec![],
            unwind: vec![],
        };
        let map = BTreeMap::from([(0x140002000, 0x140006000)]);
        prepared.bind(&map, &BTreeMap::new(), 0x140000000).unwrap();
        let body = relocate(&prepared.instructions, 0x140005000).unwrap();
        let mut decoder =
            iced_x86::Decoder::with_ip(64, &body, 0x140005000, iced_x86::DecoderOptions::NONE);
        assert_eq!(decoder.decode().near_branch_target(), 0x140006000);
        prepared
            .bind(&BTreeMap::new(), &BTreeMap::new(), 0x140000000)
            .unwrap();
        let body = relocate(&prepared.instructions, 0x140005000).unwrap();
        let mut decoder =
            iced_x86::Decoder::with_ip(64, &body, 0x140005000, iced_x86::DecoderOptions::NONE);
        assert_eq!(decoder.decode().near_branch_target(), 0x140002000);
    }

    #[test]
    fn single_byte_function_has_no_thunk_size_floor() {
        use kamy_core::{BasicBlock, Machine, Section};
        let function = Function {
            entry: Rva::new(0x1000),
            blocks: vec![BasicBlock {
                start: Rva::new(0x1000),
                end: Rva::new(0x1001),
                successors: vec![],
                terminator: Terminator::Return,
            }],
        };
        let module = Module {
            image_base: 0x140000000,
            machine: Machine::X64,
            entry_point: None,
            sections: vec![Section {
                name: ".text".into(),
                rva: Rva::new(0x1000),
                virtual_size: 1,
                data: vec![0xc3],
                flags: SectionFlags {
                    read: true,
                    write: false,
                    execute: true,
                },
            }],
            symbols: vec![],
            relocations: vec![],
            functions: vec![function.clone()],
        };
        assert_eq!(
            classify(&module, &function, &[], &HashSet::new(), &HashSet::new()),
            Ok(())
        );
    }

    #[test]
    fn retired_block_padding_contains_only_complete_nops() {
        for len in 0..64 {
            let mut bytes = Vec::new();
            append_nops(&mut bytes, len);
            assert_eq!(bytes.len(), len);
            let mut decoder =
                iced_x86::Decoder::with_ip(64, &bytes, 0x140001000, iced_x86::DecoderOptions::NONE);
            while decoder.can_decode() {
                assert_eq!(decoder.decode().mnemonic(), iced_x86::Mnemonic::Nop);
            }
        }
    }

    #[test]
    fn rejects_gs_cookie_xor_with_rsp() {
        use kamy_core::ir::{
            BlockId, Inst, IrBlock, IrFunction, IrOp, IrTerminator, IrType, ValueId,
        };

        let rsp = ValueId(0);
        let other = ValueId(1);
        let cookie = ValueId(2);
        let dest = ValueId(3);

        let make = |a: ValueId, b: ValueId| IrFunction {
            entry: BlockId(0),
            next_value: 4,
            blocks: vec![IrBlock {
                id: BlockId(0),
                phis: vec![],
                insts: vec![Inst {
                    dest: Some(dest),
                    op: IrOp::Xor,
                    args: vec![a, b],
                    ty: IrType::I64,
                }],
                term: IrTerminator::Ret,
            }],
        };

        let mut rsp_chain: HashSet<ValueId> = HashSet::new();
        rsp_chain.insert(rsp);

        // xor with the live stack pointer: the cookie framing → reject.
        assert!(accesses_caller_frame(&make(cookie, rsp), &rsp_chain));
        // ordinary xor (no rsp_chain arg) → not rejected.
        assert!(!accesses_caller_frame(&make(cookie, other), &rsp_chain));
    }
}
