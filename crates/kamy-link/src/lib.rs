//! Relocating linker: move selected functions into a new section, leave a thunk
//! at each original entry, scrub the vacated body, and rebuild the PE.

use kamy_codegen::{relocate, relocate_with_offsets, thunk};
use kamy_core::ir::{CallingConvLookup, IrFunction};
use kamy_core::{Function, Module, RejectionReason, Rva, SectionFlags};
use kamy_disasm::function_instructions;
use kamy_pe::{BytePatch, DirectoryUpdate, NewSection, PeEdits, PeFile};
use std::collections::HashMap;

const ENDBR64: [u8; 4] = [0xF3, 0x0F, 0x1E, 0xFA];
const INT3: u8 = 0xCC;
const NEAR_JMP_LEN: u32 = 5;
const FUNCTION_ALIGN: u32 = 16;

#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    #[error("codegen: {0}")]
    Codegen(#[from] kamy_codegen::CodegenError),
    #[error("pe rebuild: {0}")]
    Pe(#[from] kamy_pe::PeError),
}

pub struct Options {
    pub code_section: String,
    pub pdata_section: String,
    pub table_section: String,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            code_section: ".kamy".into(),
            pdata_section: ".kamypd".into(),
            table_section: ".kamytb".into(),
        }
    }
}

pub struct Report {
    pub moved: Vec<Rva>,
    pub rejected: Vec<(Rva, RejectionReason)>,
}

struct Moved {
    entry: Rva,
    new_rva: u32,
    new_len: u32,
}

/// Relocation-only path (Phase 1).
pub fn protect(
    pe: &PeFile,
    module: &Module,
    functions: &[Function],
    opts: &Options,
) -> Result<(Vec<u8>, Report), LinkError> {
    protect_inner(pe, module, functions, opts, |module, func, base, new_va| {
        let instrs = function_instructions(module, func);
        relocate(&instrs, base + u64::from(new_va)).map_err(LinkError::from)
    })
}

/// SSA path with IR-level transforms. Falls back to relocation when the
/// regalloc can't fit the transformed code into volatile registers.
///
/// MBA and other IR transforms are architecturally correct but produce
/// relocation-identical output until callee-saved register support lands
/// (RSP pinning + prologue/epilogue emission + UNWIND_INFO reconstruction).
pub fn protect_with_transforms(
    pe: &PeFile,
    module: &Module,
    functions: &[Function],
    opts: &Options,
    cc: &dyn CallingConvLookup,
    transform: &mut dyn FnMut(&mut IrFunction),
) -> Result<(Vec<u8>, Report), LinkError> {
    protect_inner(
        pe,
        module,
        functions,
        opts,
        |module, func, base, new_rva| {
            let new_va = base + u64::from(new_rva);
            match ssa_body(module, func, cc, transform, base, new_va) {
                Ok(body) => Ok(body),
                Err(_) => {
                    let instrs = function_instructions(module, func);
                    relocate(&instrs, new_va).map_err(LinkError::from)
                }
            }
        },
    )
}

fn ssa_body(
    module: &Module,
    func: &Function,
    cc: &dyn CallingConvLookup,
    transform: &mut dyn FnMut(&mut IrFunction),
    base: u64,
    new_va: u64,
) -> Result<Vec<u8>, LinkError> {
    let mut result = kamy_lift::lift_function(module, func, cc);
    kamy_lift::ssa::construct_ssa(&mut result);
    transform(&mut result.func);
    kamy_transforms::optimize(&mut result.func);

    // Callee-saved activation deferred to Phase 4 (needs RSP alignment
    // handling + UNWIND_INFO reconstruction). RSP pinning is active.
    let alloc =
        kamy_codegen::allocate_registers(&result.func, &[], &result.rsp_chain).map_err(|_| {
            LinkError::Codegen(kamy_codegen::CodegenError::Encode(
                "register pressure".into(),
            ))
        })?;

    let instrs = kamy_codegen::select_instructions(&result.func, &alloc, base, new_va, &[]);
    relocate(&instrs, new_va).map_err(LinkError::from)
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
    mut produce_body: impl FnMut(&Module, &Function, u64, u32) -> Result<Vec<u8>, LinkError>,
) -> Result<(Vec<u8>, Report), LinkError> {
    let base = module.image_base;
    let table_base_rva = pe.next_section_rva().get();
    let sect_align = pe.section_alignment();
    let runtime_fns = pe.runtime_functions();
    let import_slots: std::collections::HashSet<u32> =
        pe.import_slots().iter().map(|r| r.get()).collect();

    let mut report = Report {
        moved: Vec::new(),
        rejected: Vec::new(),
    };
    let mut code: Vec<u8> = Vec::new();
    let mut moved: Vec<Moved> = Vec::new();
    let mut pending_patches: Vec<BytePatch> = Vec::new();

    let mut ordered: Vec<&Function> = functions.iter().collect();
    ordered.sort_by_key(|f| f.entry.get());

    // Pass 1: size the table section so the code base is fixed before any body
    // is relocated — switch dispatches must point at the final table VAs.
    let mut total_tables: u32 = 0;
    for func in &ordered {
        if let Ok(cand) = classify(module, func, &runtime_fns, &import_slots) {
            for t in &cand.switches {
                total_tables = total_tables.saturating_add(t.count.saturating_mul(4));
            }
        }
    }
    let code_rva = if total_tables > 0 {
        align_up(table_base_rva.saturating_add(total_tables), sect_align)
    } else {
        table_base_rva
    };
    let mut tables: Vec<u8> = Vec::with_capacity(total_tables as usize);

    for func in ordered {
        match classify(module, func, &runtime_fns, &import_slots) {
            Ok(cand) => {
                pad_to_align(&mut code, FUNCTION_ALIGN);
                let new_rva = code_rva + code.len() as u32;
                let new_va = base + u64::from(new_rva);

                let body = if cand.switches.is_empty() {
                    match produce_body(module, func, base, new_rva) {
                        Ok(b) => b,
                        Err(_) => {
                            report
                                .rejected
                                .push((func.entry, RejectionReason::CodegenFailure));
                            continue;
                        }
                    }
                } else {
                    match build_switch_body(
                        module,
                        func,
                        base,
                        new_va,
                        table_base_rva,
                        &mut tables,
                        &cand.switches,
                    ) {
                        Ok(b) => b,
                        Err(()) => {
                            report
                                .rejected
                                .push((func.entry, RejectionReason::RecoverableSwitch));
                            continue;
                        }
                    }
                };

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
                moved.push(Moved {
                    entry: cand.entry,
                    new_rva,
                    new_len: body.len() as u32,
                });
                pending_patches.extend(patches);
            }
            Err(Some(reason)) => report.rejected.push((func.entry, reason)),
            Err(None) => {}
        }
    }

    if moved.is_empty() {
        return Ok((pe.rebuild(&PeEdits::default())?, report));
    }

    let code_len = code.len() as u32;
    let mut new_sections: Vec<NewSection> = Vec::new();
    if total_tables > 0 {
        debug_assert_eq!(tables.len() as u32, total_tables);
        new_sections.push(NewSection {
            name: opts.table_section.clone(),
            rva: Rva::new(table_base_rva),
            flags: SectionFlags {
                read: true,
                write: false,
                execute: false,
            },
            data: tables,
        });
    }
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
    let mut directories = Vec::new();

    if !runtime_fns.is_empty() {
        let moved_by_entry: HashMap<u32, &Moved> =
            moved.iter().map(|m| (m.entry.get(), m)).collect();
        let pdata = rebuild_pdata(&runtime_fns, &moved_by_entry);
        let pdata_rva = align_up(code_rva + code_len, pe.section_alignment());
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
    Ok((pe.rebuild(&edits)?, report))
}

struct Candidate {
    entry: Rva,
    end: u32,
    endbr: bool,
    switches: Vec<kamy_core::SwitchTable>,
}

fn classify(
    module: &Module,
    func: &Function,
    runtime_fns: &[kamy_pe::RuntimeFunction],
    import_slots: &std::collections::HashSet<u32>,
) -> Result<Candidate, Option<RejectionReason>> {
    let entry = func.entry;
    if !module.is_executable(entry) {
        return Err(None);
    }
    let end = func
        .blocks
        .iter()
        .map(|b| b.end.get())
        .max()
        .unwrap_or(entry.get());
    let size = end.saturating_sub(entry.get());

    use kamy_core::Terminator::{Indirect, Switch, Unknown};
    let mut switches = Vec::new();
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
            // D24 layer 2: table recovered — re-emit it and retarget the
            // dispatch when the function moves (build_switch_body).
            Switch { table } => switches.push(table.clone()),
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

    Ok(Candidate {
        entry,
        end,
        endbr,
        switches,
    })
}

/// Encode one relocated table entry. LLVM table-relative: signed i32 delta from
/// the new table VA. MSVC module-base: the target's new RVA. Err on i32 overflow
/// or a target below the image base (reject-on-ambiguity, never emit a guess).
fn encode_entry(
    base: u64,
    new_table_va: u64,
    base_is_image: bool,
    new_target_va: u64,
) -> Result<[u8; 4], ()> {
    if base_is_image {
        let rva = u32::try_from(new_target_va.checked_sub(base).ok_or(())?).map_err(|_| ())?;
        Ok(rva.to_le_bytes())
    } else {
        let delta = i32::try_from(new_target_va as i64 - new_table_va as i64).map_err(|_| ())?;
        Ok(delta.to_le_bytes())
    }
}

/// Relocate a switch function to `new_va`, retargeting each dispatch to a fresh
/// table appended to `tables` (based at image `base + table_base_rva`). Returns
/// the relocated body; the tables buffer is filled in place. Err (reject) if any
/// dispatch instruction is missing, any case target has no stable new address,
/// or an entry overflows — the caller then keeps the function in place.
fn build_switch_body(
    module: &Module,
    func: &Function,
    base: u64,
    new_va: u64,
    table_base_rva: u32,
    tables: &mut Vec<u8>,
    switches: &[kamy_core::SwitchTable],
) -> Result<Vec<u8>, ()> {
    let mut instrs = function_instructions(module, func);
    // Reserve each table's slot and retarget its dispatch BEFORE relocating.
    let mut plans: Vec<(usize, u64, &kamy_core::SwitchTable)> = Vec::new();
    for t in switches {
        let start = tables.len();
        tables.extend(std::iter::repeat_n(0u8, t.count as usize * 4));
        let table_rva = table_base_rva + start as u32;
        let new_table_va = base + u64::from(table_rva);
        let disp = if t.base_is_image {
            u64::from(table_rva)
        } else {
            new_table_va
        };
        let ins = instrs
            .iter_mut()
            .find(|i| (i.ip().wrapping_sub(base)) as u32 == t.dispatch_rva.get())
            .ok_or(())?;
        ins.set_memory_displacement64(disp);
        plans.push((start, new_table_va, t));
    }
    let (code, offsets) = relocate_with_offsets(&instrs, new_va).map_err(|_| ())?;
    let mut map: HashMap<u32, u64> = HashMap::new();
    for (i, ins) in instrs.iter().enumerate() {
        if offsets[i] != u32::MAX {
            map.insert(
                (ins.ip().wrapping_sub(base)) as u32,
                new_va + u64::from(offsets[i]),
            );
        }
    }
    for (start, new_table_va, t) in plans {
        for (k, entry) in t.entries.iter().enumerate() {
            let new_target_va = *map.get(&entry.get()).ok_or(())?;
            let bytes = encode_entry(base, new_table_va, t.base_is_image, new_target_va)?;
            let o = start + k * 4;
            tables[o..o + 4].copy_from_slice(&bytes);
        }
    }
    Ok(code)
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
) -> Vec<u8> {
    let mut entries: Vec<(u32, u32, u32)> = runtime_fns
        .iter()
        .map(|rf| match moved.get(&rf.begin.get()) {
            Some(m) => (m.new_rva, m.new_rva + m.new_len, rf.unwind.get()),
            None => (rf.begin.get(), rf.end.get(), rf.unwind.get()),
        })
        .collect();
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
    fn llvm_entries_round_trip_to_new_targets() {
        let base = 0x1_4000_0000u64;
        let new_table_va = 0x1_4005_0000u64;
        for new_target_va in [0x1_4004_8000u64, 0x1_4006_1230u64] {
            let bytes = encode_entry(base, new_table_va, false, new_target_va).unwrap();
            let delta = i32::from_le_bytes(bytes);
            assert_eq!((new_table_va as i64 + delta as i64) as u64, new_target_va);
        }
    }

    #[test]
    fn llvm_equal_targets_encode_equal() {
        let base = 0x1_4000_0000u64;
        let new_table_va = 0x1_4005_0000u64;
        let target = 0x1_4004_8000u64;
        let a = encode_entry(base, new_table_va, false, target).unwrap();
        let b = encode_entry(base, new_table_va, false, target).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn msvc_entries_round_trip_to_new_targets() {
        let base = 0x1_4000_0000u64;
        let new_table_va = 0x1_4005_0000u64;
        let new_target_va = 0x1_4006_1230u64;
        let bytes = encode_entry(base, new_table_va, true, new_target_va).unwrap();
        let rva = u32::from_le_bytes(bytes);
        assert_eq!(base + u64::from(rva), new_target_va);
    }

    #[test]
    fn llvm_delta_overflow_rejects() {
        let base = 0x1_4000_0000u64;
        let new_table_va = 0x1_4000_0000u64;
        let new_target_va = new_table_va + (i32::MAX as u64) + 2;
        assert!(encode_entry(base, new_table_va, false, new_target_va).is_err());
    }

    #[test]
    fn msvc_target_below_base_rejects() {
        let base = 0x1_4000_0000u64;
        let new_table_va = 0x1_4005_0000u64;
        let new_target_va = base - 0x1000;
        assert!(encode_entry(base, new_table_va, true, new_target_va).is_err());
    }
}
