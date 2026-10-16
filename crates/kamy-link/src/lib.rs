//! Relocating linker: move selected functions into a new section, leave a thunk
//! at each original entry, scrub the vacated body, and rebuild the PE.

use std::collections::HashMap;

use kamy_codegen::{relocate, thunk};
use kamy_core::ir::{CallingConvLookup, IrFunction};
use kamy_core::{Function, Module, RejectionReason, Rva, SectionFlags};
use kamy_disasm::function_instructions;
use kamy_pe::{BytePatch, DirectoryUpdate, NewSection, PeEdits, PeFile};

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
}

impl Default for Options {
    fn default() -> Self {
        Self {
            code_section: ".kamy".into(),
            pdata_section: ".kamypd".into(),
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
    let code_rva = pe.next_section_rva().get();
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

    for func in ordered {
        match classify(module, func, &runtime_fns, &import_slots) {
            Ok(cand) => {
                pad_to_align(&mut code, FUNCTION_ALIGN);
                let new_rva = code_rva + code.len() as u32;

                let body = match produce_body(module, func, base, new_rva) {
                    Ok(b) => b,
                    Err(_) => {
                        report
                            .rejected
                            .push((func.entry, RejectionReason::CodegenFailure));
                        continue;
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
    let mut new_sections = vec![NewSection {
        name: opts.code_section.clone(),
        rva: Rva::new(code_rva),
        flags: SectionFlags {
            read: true,
            write: false,
            execute: true,
        },
        data: code,
    }];
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
