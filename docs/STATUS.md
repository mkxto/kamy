# Kamy — Project Status

Living document. Updated as work lands.

---

## Phase 1 — Foundation ✅

| Item | Status | Commit |
|------|--------|--------|
| Workspace scaffold (12 crates, CI) | Done | `36e3d88` |
| PE parser (headers, sections, .reloc, .pdata, imports, exports) | Done | `de40116` |
| PE emitter (byte-surgery rebuild, append section, patch, dirs) | Done | `b29b83b` |
| Disassembler (iced-x86 decode, CFG, function discovery) | Done | `de40116` |
| Container IR (Module, Section, Symbol, Relocation, Function, BasicBlock) | Done | `de40116` |
| YAML config schema (serde_norway, full CodeDefender shape) | Done | `36e3d88` |
| CLI: `analyze` (parse → discover → report) | Done | `de40116` |
| Dominator tree + dominance frontiers | Done | `ceb49e1` |

## Phase 2 — SSA IR Engine 🔶

| Item | Status | Notes |
|------|--------|-------|
| SSA IR types (ValueId, BlockId, IrType, 40+ IrOp, Phi, IrBlock, IrFunction, PhysReg, CallingConvLookup) | Done | `1cfc37b` |
| Semantic lifter (all D6 ops: GPR arith/logic/data/control + SSE data movement) | Done | `1cfc37b` |
| NativeInline fallback (iced-x86 InstructionInfoFactory → clobber sets) | Done | `1cfc37b` |
| SSA construction (maximal phi, RPO traversal, cross-block register threading) | Done | `1cfc37b`, threading fixed (RPO + block_exit propagation) |
| Optimizer (constprop, instcombine, DCE, prune-phis, convergence) | Done | `1cfc37b` |
| DCE live-out fix (`Use` ops before `Ret` for RAX + callee-saved) | Done | `88e9e8a` |
| Register allocator (linear-scan, zero-spill hard constraint) | Done | `1cfc37b` |
| Instruction selector (IR → x86, flag fusion, NativeInline re-emit) | Done | `1cfc37b` |
| RSP pinning (lifter tracks RSP chain, regalloc pins to physical RSP) | Done | `26216be` |
| Callee-saved activation (moved from Phase 4, D31) | **Next** | Push/pop emission + RSP alignment shim + drop live-through `Use` pins (control.rs:118-133) |
| Relocating linker (thunks, .kamy section, .pdata rebuild, scrub) | Done | `b29b83b` |
| SSA linker path (lift→ssa→opt→regalloc→isel→encode + fallback) | Done | `13196a1` |
| No-transform relocation round-trip (169 functions, verified) | ✅ Proven | `b29b83b` |
| No-transform SSA round-trip (shipped config) | ⚠️ 0/169 shipped | Callee-saved disabled (`&[]`) → zero-spill `RegisterPressure`; falls back to relocation. exit=7 is relocation. |
| SSA lowering reachability (callee-saved pool enabled, diagnostic) | 95/169 regalloc-ready | Proves the SSA engine lowers real functions once the pool is available. Remaining 74: 70 zero-spill pressure, 4 XMM5 encode bug. |
| MBA pass (add/sub/xor rules, D13 config shape) | Done | `1cfc37b` |
| MBA probability fix | Done | `fa6b941` |
| MBA visible output | **Blocked** | Gated on callee-saved activation (now a Phase 2 item, D31). Lifter threading no longer blocks it (fixed). |
| Win32metadata calling-convention DB | Deferred | Trait wired + Win64Default + WinmdLookup todo!() |
| Pressure-aware transform budgeting (D28) | Planned | Degrade pass intensity on RegisterPressure; zero-spill stands |
| .pdata/UNWIND_INFO emission for generated prologues (moved from Phase 4, D31) | Not started | Plain functions only; SEH functions stay rejected |
| Differential self-test harness (kamy-verify) | Not started | Original vs protected: stdout + exit code diff; the Phase 2 shipping gate |

### Known bugs

1. ✅ **FIXED — RSP/callee-saved not threaded across blocks.** Registers unchanged
   through a block kept their block-entry `Undef`; φ-nodes then referenced dead undefs
   → artificial `RegisterPressure`. Root cause was SSA construction (`ssa.rs`), not
   `lift_call` (its clobber list is volatiles-only). Fix: RPO traversal + propagate
   the resolved value into `block_exit` after each replacement. Verified on `fib`
   (RSP now threads as `v43`); SSA lowering reachability went 0 → 95/169.
2. **XMM5 memory-operand encode failure.** 4 functions fall back with
   `mov xmm5,[reg]` encode errors in isel/codegen. Separate from threading.
3. **Zero-spill register pressure.** 70/169 functions exceed 15 GPRs under the D5
   zero-spill constraint; need XMM callee-saved or a spill path. Expected gap.
4. **Return-address push is materialized.** `Store(rsp, const_return_addr)` before
   Call could be folded into the Call node. Optimization, not correctness.
5. **Over-approximated call args.** Win64Default passes 4 args for every call.
   Resolved by Win32metadata DB (D14) or PDB symbol lookup.
6. ✅ **MOSTLY FIXED — Runaway function recovery.** Recovery followed far branch
   targets across `.pdata` boundaries, producing functions with multi-hundred-KiB
   spans (kernel32 max 478 KiB) that swallowed neighbors, falsely tripped
   `SEHComplex` (multiple unwind frags in the bloated range), and inflated
   counts. Fix (`kamy-disasm`): bound each function's recovery at the next
   `.pdata`/export/entry start — those partition x64 code into non-overlapping
   ranges — and treat `jmp` to a known start as a tail call. Measured: kernel32
   max span 478 KiB → 17.7 KiB (oversized >16 KiB: 17 → 1), target.exe 84 KiB →
   2.9 KiB (19 → 0); `moved` rose (kernel32 1214 → 1271, target 169 → 197) as
   mis-`SEHComplex` functions reclassified. Residual: a handful of phantom
   call-seeds still land inside real code (target 2, kernel32 1); eliminating
   them needs noreturn tracking (post-noreturn-call bytes decoded as fallthrough
   now truncate to a `LiftFailure` reject instead of corrupting). See
   research.md §10.2.

## Phase 3 — SEH & CET (D31: correctness before obfuscation)

| Item | Status |
|------|--------|
| Full UNWIND_INFO reconstruction (SEH functions: scope tables, handler re-pointing, chained unwind) | Not started |
| C_SCOPE_TABLE re-pointing | Not started |
| CET shadow stack reconciliation | Not started |
| MSVC SEH test suite (58+ tests, D11) | Not started |

## Phase 4 — Obfuscation Passes

| Item | Status |
|------|--------|
| ObscureReferences | Not started |
| ObscureConstants | Not started |
| MutationEngine | Not started |
| LoopEncodeSemantics | Not started (underspecified — needs design) |
| Per-function config profiles + symbol matching | Not started |
| Jump table recovery & retargeting (D24) | Layer 0 done | `jmp [rip+slot]` classified at discovery (`Terminator::Indirect { slot }`); link skips import/forwarder thunks (IAT-slot) and reports in-image static-ptr tail-calls as `ResolvableIndirect`. Measured (post runaway-recovery fix): kernel32 `BadIndirectBranch` 922→9, target.exe 114→30. Remaining: noreturn tracking → layer 2 use-def DAG + petgraph VF2 → re-emit/retarget (our own gap) |
| Trampoline stub obfuscation (D29: flavor diversification + junk fill + direct-call re-pointing) | Not started |

## Phase 5 — Advanced Passes

Not started. CFF, opaque predicates, polynomial MBA, dead-code injection,
known-bits abstract domain, cost-gated expression simplifier.

## Phase 6 — Production

Not started. Coverage reporting, API server, CI integration, ELF, ARM64.

## Phase 7 — Runtime & Plugin SDK (D30)

Not started. EP hijack + init-callback table, runtime sections (RX/RW/R),
lazy imports / feature dispatch / integrity helpers, plugin COFF ingestion,
TLS/CET-safe entry stub.

---

## Ground truth — CodeDefender RE (2026-10-16)

Source: RE of `HelloWorld-Injected.exe` (codedefender-io/plugins) — the model we replicate.

- Trampolines confirmed: plain `E9 rel32` detours at original entries (D2 validated).
- Packer layout: `.belabs` RX/RW/R sections; EP hijack 0x1320→0x152d with init-callback table; old `.pdata` repurposed as code, fresh `.pdata` appended.
- SDK: LLVM-MSVC toolchain, init-table linker symbols, lazy_importer — recorded as D30.

Open external threads: confirm `sub_140007000` purpose (import resolver vs anti-tamper);
enumerate the full trampoline set (5 verified: 0x1000, 0x1070, 0x10c0, 0x17c8, 0x1d54);
inspect the init callbacks at `.rdata` 0x27f0.


## Test corpus

| Test | Status |
|------|--------|
| Unit tests (across 7 crates, incl. SSA threading) | ✅ All pass |
| Relocation round-trip (target.exe, 169 functions) | ✅ Verified (exit=7, ASLR-stable) |
| SSA identity round-trip (target.exe) | ⚠️ exit=7 via relocation fallback (callee-saved disabled); engine reaches 95/169 regalloc-ready with pool |
| kernel32.dll analysis (2588 functions, 29717 blocks) | ✅ Verified (headers cross-checked) |
| aftermathlabs/bintests corpus (D25) | Not adopted |
| backengineering/bintests `misc/jtables` — jump-table corpus (research.md §10.5) | Not adopted |

## Rejection rates

| Binary | Moved | Rejected | Rate | Top rejection |
|--------|-------|----------|------|---------------|
| target.exe (Rust) | 197 | 152 | 56.4% | LiftFailure (94) |
| kernel32.dll | 1271 | 438 | 74.4% | SEHComplex (396) |

Two correctness fixes landed since the §10 study.

**D24 layer 0** (`jmp [rip+slot]` classification): kernel32 `BadIndirectBranch`
922 → **9** (genuine register/indexed dispatch only) plus `ResolvableIndirect`
(in-image static-pointer tail-calls, direct-ification pending); import/forwarder
thunks are **skipped** (not protection targets). target.exe `BadIndirectBranch`
114 → **30**; `jmp [__imp_…]` import thunks skipped (exact IAT-slot membership
is finer than §10.2's coarse ".rdata window" bucket).

**Runaway-recovery fix** (known bug #6): bounding recovery at the next
`.pdata`/export/entry start removed the 478 KiB phantom spans, so `moved` rose
(kernel32 1214 → 1271, target 169 → 197) as functions previously mis-flagged
`SEHComplex` reclassified; post-noreturn fallthrough now truncates to a
conservative `LiftFailure` instead of swallowing the next function. target.exe
round-trip still reproduces `acc=0x97a61ac866cf61c7` (exit 7) after both fixes.

Remaining D24 order: residual phantom call-seeds / noreturn tracking → layer 2
(use-def DAG + petgraph VF2) for the residual `BadIndirectBranch`.

Jump table recovery (D24) is the #1 coverage improvement.
