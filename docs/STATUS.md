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
| Callee-saved activation (D31) | ✅ Done | Pool enabled; push/pop + RSP 16-byte align shim; dropped live-through `Use` pins. Required the SSA backend ABI-correctness pass below to ship correctly. |
| Relocating linker (thunks, .kamy section, .pdata rebuild, scrub) | Done | `b29b83b` |
| SSA linker path (lift→ssa→opt→regalloc→isel→encode + fallback) | Done | `13196a1` |
| No-transform relocation round-trip (169 functions, verified) | ✅ Proven | `b29b83b` |
| No-transform SSA round-trip (coverage = SSA-lowered) | ✅ Verified, honest metric | Coverage counts **only** SSA-lowered functions; verbatim relocation (a "weak move") is now reported as a reject with its real reason, not as coverage. `sw`/`sw2`/`sw3`/`target`/`flag`/`hex` reproduce exact output, `kamy verify` PASS (deterministic). kernel32.dll: **430/1751 (~24.5%) via SSA**; rejects dominated by `RegisterPressure 848` (zero-spill D5 + over-approx call args D14), `SEHComplex 395`, `UnsupportedInstruction 39`. Full taxonomy in `kamy-core::RejectionReason`. |
| SSA backend ABI + control-flow correctness (D31) | ✅ Done | The backend had never emitted correct code. Fixed across `08ff18c`/`23a792e`/`cd61f2a`/`167cc98`: multi-block phi destruction (sequentialized edge copies + critical-edge landing blocks) and branch resolution (sentinel block IPs so iced `BlockEncoder` links intra-function jumps); subtract-comparison flags lower to `cmp a,b` (was `test a,a`); I8 flag values get distinct registers (was hard-pinned to RAX, so compound conditions clobbered each other); deterministic interval ordering; non-pinned values avoid any register pinned by an overlapping interval (replacing an unsound mid-life eviction copy that clobbered live values such as the frame pointer); RIP-relative data; indirect calls; direct tail calls (`IrTerminator::Tail` with ABI arg liveness + frame teardown before the jmp); `CallIndirect` as a DCE root. Add- and constant-shift-based condition flags consumed by a branch/`setcc` lower by re-executing the op into a reserved R11 scratch (`mov r11,a; add r11,b; jcc`). **Residual conservative relocations (sound, D22):** self-recursive functions (lowered frame too large — needs D5 stack-frame reconstruction), functions branching on a variable-count shift flag (reproducing it needs CL, which the allocator does not model), unmodeled (NativeInline) RIP-relative instructions, indirect / switch `Unknown` terminators (indirect tail jmps included), and genuine >15-register pressure (D5 zero-spill, reducible with the D14 cc DB). |
| MBA pass (add/sub/xor rules, D13 config shape) | Done | `1cfc37b` |
| MBA probability fix | Done | `fa6b941` |
| MBA visible output | ✅ Done | Exposed two real lowering bugs (now fixed): constant shifts routed the count through `CL`, clobbering a live RCX the allocator does not model — now emit the immediate-form shift (`shl r,imm`); and `emit_void` hardcoded I64 store width, truncating sub-qword stores — now threads the real operand width. `sw`/`sw2`/`sw3`/`target` with MBA (`probability:100`): exit matches original, `kamy verify` PASS (200 runs), output deterministic, bytes differ from `probability:0`. **94/203 via SSA** on `sw` (was a deterministic crash before the fix). |
| Win32metadata calling-convention DB | Deferred | Trait wired + Win64Default + WinmdLookup todo!() |
| Pressure-aware transform budgeting (D28) | Partial | Intensity knob on the MBA pass landed (`run_with_intensity`); the retry-at-lower-intensity ladder is not wired. |
| .pdata/UNWIND_INFO emission for generated prologues (D31) | ✅ Done | `.kamyxd` section + UNWIND_INFO describing the push/align prologue; body frame-alloc codes are Phase 3. |
| Differential self-test harness (kamy-verify) | ✅ Done | `kamy verify --original X --protected Y`: exit + stdout diff over N seeded runs. The Phase 2 shipping gate. |

### Known bugs

1. ✅ **FIXED — RSP/callee-saved not threaded across blocks.** Registers unchanged
   through a block kept their block-entry `Undef`; φ-nodes then referenced dead undefs
   → artificial `RegisterPressure`. Root cause was SSA construction (`ssa.rs`), not
   `lift_call` (its clobber list is volatiles-only). Fix: RPO traversal + propagate
   the resolved value into `block_exit` after each replacement. Verified on `fib`
   (RSP now threads as `v43`); SSA lowering reachability went 0 → 95/169.
2. ✅ **FIXED — XMM5 memory-operand encode failure.** A 128-bit memory source
   lifts to `Load:I128`, which the allocator places in an XMM register, but isel
   emitted the GPR `mov r64,[mem]` for it; iced builds that instruction yet
   `BlockEncoder` rejects it, so the linker relocated the function verbatim. isel
   now routes every XMM-assigned Load/Store/Const-zero/Copy/Xor through the SSE
   forms (`movss`/`movsd`/`movups`/`movaps`/`xorps`/`movq`). Recovered +4 on an SSE
   fixture, +16 on kernel32.
3. ✅ **FIXED — Zero-spill XMM register pressure.** XMM6–XMM15 are now a
   callee-saved pool: a 128-bit value that crosses a call lands there, saved with
   `movups` in the generated prologue (one combined `sub rsp` folds the alignment
   pad and the 16-byte save slots) and described as a `UWOP_ALLOC` in `UNWIND_INFO`.
   `SAVE_XMM128` for the individual stores needs a 16-aligned frame — incompatible
   with keeping the lowered body at `rsp%16==8` without a frame pointer — so the
   per-register restore on an exception unwind is deferred to full SEH (D31 Phase
   3); the ALLOC alone keeps stack walks correct. Demonstrated: a fixture whose
   function keeps eight vectors across a call lowers via SSA into XMM6–XMM13 and
   `verify` PASS.
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
   mis-`SEHComplex` functions reclassified. Noreturn tracking followed: a trap
   (`ud2`, `int`) or a call through a known-noreturn import slot now ends the
   block, so over-decoded fallthrough no longer truncates to `LiftFailure`
   (target 94 → 71, kernel32 20 → 17; `moved` 197 → 202 / 1271 → 1274). Residual:
   2–3 phantom call-seeds still land inside real code via data-in-code, not
   over-decode — a local-noreturn fixpoint / data-in-code handling is the
   remaining lever. See research.md §10.2.
7. **Volatile-pinned GPR live across a call is rejected, not recovered.** A reg→reg
   `mov` aliases the source value in the lifter, so an incoming argument moved into
   a callee-saved register (`mov rsi, r8; call; use rsi`) stays pinned to its
   *volatile* source register; kept across the call, that register is clobbered.
   The allocator now rejects such functions (relocates verbatim) instead of
   miscompiling — surfaced when the XMM pool (bug 3) let these functions past the
   old XMM-pressure reject. Correct but conservative: it dropped kernel32
   SSA-lowered 488 → 430 by rejecting ~58 previously-unsound lowerings (kernel32 is
   not executed, so those miscompiles were never caught). The real fix is live-range
   splitting / shrink-wrapping — move the value into a callee-saved register for its
   cross-call span. A blanket "Copy every volatile-sourced `mov`" perturbs
   allocation enough to clobber loop-carried values (regressed hex formatting), so
   the split must be targeted.

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
| LoopEncodeSemantics | Not started (design settled: add/sub/and/xor as carry/bit-propagation loops — research.md §2.8) |
| Per-function config profiles + symbol matching | Not started |
| Jump table recovery & retargeting (D24) | Layers 0 + 2 (detect + **retarget**) done | Layer 0: `jmp [rip+slot]` classified at discovery; link skips import thunks, reports in-image static-ptr as `ResolvableIndirect`. Layer 2 detect: per-function use-def DAG + petgraph VF2 (research.md §10.5) recovers the table (bound-or-reject, in-range cross-check) and tags `Terminator::Switch`. **Phase B (retarget):** recovery materializes case bodies as blocks; the linker re-emits each table into a read-only `.kamytb` section and retargets the dispatch (LLVM `lea`→new table VA; MSVC `mov` disp→new table RVA), overriding `BlockEncoder`'s RIP fixup via an original→new address map from the encoder's instruction offsets. Runtime-verified: the `sw` fixture dispatch moves and `sw.prot` prints `acc=0xade56742d39ef7e2` (exit 34); target round-trip `acc=0x97a61ac866cf61c7` (exit 7); kernel32 MSVC form (incl. a 4-table function) rebuilds. `RecoverableSwitch`→0. Coverage rises modestly (target 202→203, kernel32 1274→1276, `sw` +2) because most recovered-switch functions carry orthogonal **out-of-scope** blockers — SEH unwind (`SEHComplex`, D31), noreturn/data-in-code tails (`LiftFailure`, §10.2 residual), or a genuine second register dispatch (`BadIndirectBranch`). |
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


## Runnable differential corpus (issue #7, D33–D36)

`kamy corpus {build,bless,verify,list} --corpus <checkout>` drives a
multi-toolchain member set in `github.com/mkxto/kamy-corpus` (pinned by
`corpus.lock`). Each member declares an oracle; `verify` compares the protected
binary to a committed golden record blessed from the original and reports SSA
lift/lower coverage beside the pass/fail verdict. Open tool, not a CI gate (D33).

| Member | Toolchain | Oracle | verify | SSA / reloc / reject | coverage |
|--------|-----------|--------|--------|----------------------|----------|
| console_fibmix | rustc | stdio | ✅ PASS | 0 / 203 / 146 | 0/349 |
| gui_msgbox | msvc (cl) | winapi link-shim trace | ✅ PASS | 0 / 394 / 131 | 0/525 |
| dll_strutil | msvc (cl) | loader / pure exports | ✅ PASS | 0 / 266 / 96 | 0/362 |
| kernel32 (vendored) | prebuilt | loader / pure exports | ✅ PASS | 0 / 1276 / 433 | 0/1709 |

- gui trace comes from a build-time winapi link-shim (no DLL injection):
  `MessageBoxW|hello world`, `MessageBoxW|second`.
- dll members run under a loader that maps a uniquely-named copy — defeating the
  KnownDLLs short-circuit so kernel32's real bytes execute — and calls curated
  pure exports (`MulDiv(6,7,3)=14`, `lstrlenW=5`, `kamy_fnv("abc")=440920331`).
- Coverage = SSA-lowered / total; **relocated and rejected are both not-covered**
  (verbatim relocation is not SSA coverage). `--no-transform` lowers 0 via SSA, so
  coverage reads 0% today and climbs as SSA-forcing transforms land.
- Negative-tested: a tampered golden makes `verify` exit non-zero and flag the
  diverging member (the oracle is not a tautology).
- `corpus build` needs the toolchains (cl via `vcvars64.bat` / rustc; clang-cl
  skipped when absent); `corpus verify` consumes the published originals +
  goldens and needs no compiler (D34).
- **Host note:** a protection engine's outputs are inherently AV-flagged. The
  corpus work dir must be excluded from real-time AV
  (`Add-MpPreference -ExclusionPath 'C:\dev\kamy-corpus'`) or Defender
  quarantines generated/protected DLLs (`err 225`).

## Test corpus

| Test | Status |
|------|--------|
| Unit tests (across 7 crates, incl. SSA threading) | ✅ All pass |
| Relocation round-trip (target.exe, 169 functions) | ✅ Verified (exit=7, ASLR-stable) |
| SSA identity round-trip (sw/sw2/sw3/target.exe) | ✅ Verified | Exact accumulators + `kamy verify` PASS; ~85 functions/binary lowered via SSA (multi-block, rip-rel, indirect calls), rest relocate. |
| kernel32.dll SSA round-trip (2588 functions) | ✅ Verified (static) | Rebuilds via SSA (362 lowered); re-parses as valid PE, exports preserved, exception table consistent (1608/1608 RUNTIME_FUNCTIONs). DLL — not executed. |
| aftermathlabs/bintests corpus (D25) | Not adopted |
| backengineering/bintests `misc/jtables` — jump-table corpus (research.md §10.5) | Not adopted |
| Runnable corpus (issue #7): console/gui/dll/kernel32 | ✅ 4/4 PASS | Golden-record verify + SSA coverage; kernel32 pure exports now executed (loader). |

## Rejection rates

| Binary | Moved | Rejected | Rate | Top rejection |
|--------|-------|----------|------|---------------|
| target.exe (Rust) | 203 | 146 | 58.2% | LiftFailure (77) |
| kernel32.dll | 1276 | 433 | 74.7% | SEHComplex (396) |

Three correctness fixes landed since the §10 study.

**D24 layer 0** (`jmp [rip+slot]` classification): kernel32 `BadIndirectBranch`
922 → **9** (genuine register/indexed dispatch only) plus `ResolvableIndirect`
(in-image static-pointer tail-calls, direct-ification pending); import/forwarder
thunks are **skipped** (not protection targets). target.exe `BadIndirectBranch`
114 → **30**; `jmp [__imp_…]` import thunks skipped (exact IAT-slot membership
is finer than §10.2's coarse ".rdata window" bucket).

**Runaway-recovery + noreturn fix** (known bug #6): bounding recovery at the next
`.pdata`/export/entry start removed the 478 KiB phantom spans, and traps
(`ud2`/`int`) plus known-noreturn import calls now end the block. `moved` rose
(kernel32 1214 → 1274, target 169 → 202) as functions previously mis-flagged
`SEHComplex` reclassified and over-decoded tails stopped truncating to
`LiftFailure` (target 94 → 71, kernel32 20 → 17). target.exe round-trip still
reproduces `acc=0x97a61ac866cf61c7` (exit 7) after all three fixes.

**D24 layer 2 (detect + retarget)** (use-def DAG + petgraph VF2, research.md
§10.5): recovery matches the dispatch, derives the bounded entry count, parses
the ordered table (duplicates preserved), and **materializes the case bodies as
blocks** so a switch function relocates as one unit. `BadIndirectBranch` dropped
(kernel32 9 → **6**, target.exe 30 → **19**). On the runnable fixture all 16
cases recover exactly and `sw.prot` reproduces `acc=0xade56742d39ef7e2` (exit 34).

**Phase B — retarget (landed).** The linker re-emits each recovered table into a
read-only `.kamytb` section laid out *before* the moved code (so the new table
VA is known pre-relocation) and redirects the dispatch operand — LLVM `lea` →
new table VA, MSVC `mov` displacement → new table RVA — overriding
`BlockEncoder`'s RIP auto-fixup. Entries are recomputed per form (LLVM signed
i32 delta `new_target_va - new_table_va`; MSVC `new_target_rva`) from an
original→new address map built out of `BlockEncoder`'s returned instruction
offsets; any unmapped target, rewritten-instruction offset, or i32 overflow
keeps the function rejected (`RecoverableSwitch`, reject-on-ambiguity, D24/§10.5).
Runtime-verified: both round-trips reproduce their accumulators (`sw` exit 34,
target `acc=0x97a61ac866cf61c7` exit 7); the kernel32 MSVC form (including a
single function carrying four tables) rebuilds and re-parses with a consistent
`.pdata` (not executed here — DLL).

`RecoverableSwitch` is now **0** on all three binaries, but `moved` rises only
modestly (target 202 → **203**, kernel32 1274 → **1276**, `sw` +2 including the
fixture dispatch). Only recovered-switch functions with no other blocker move;
the rest reject under their *true* reason, each **out of scope for Phase B**: SEH
unwind info (`SEHComplex`, needs D31 UNWIND reconstruction), a noreturn/
data-in-code tail that leaves an `Unknown` block (`LiftFailure`, the §10.2
local-noreturn residual), or a genuine second register dispatch
(`BadIndirectBranch`). Lifting those is future work, not a retarget defect.
