# Kamy — Project Status

Living document. Updated as work lands.
Current repair evidence is recorded in the final campaign section. Earlier relocation, SDK and corpus measurements are historical snapshots, not acceptance of the D40 cutover.

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
| Historical register allocator (linear-scan, zero-spill hard constraint) | Superseded by H2 | `1cfc37b`; the final H2 campaign below records the memory-backed cutover. |
| Instruction selector (IR → x86, flag fusion, NativeInline re-emit) | Done | `1cfc37b` |
| RSP pinning (lifter tracks RSP chain, regalloc pins to physical RSP) | Done | `26216be` |
| Callee-saved activation (D31) | ✅ Done | Pool enabled; push/pop + RSP 16-byte align shim; dropped live-through `Use` pins. Required the SSA backend ABI-correctness pass below to ship correctly. |
| Reference-rewriting linker (.kamy, inbound/outbound refs, directory rebuild) | Done | D37; no original-entry thunks or `NoThunkSpace`; current #17 evidence below |
| SSA linker path (lift→ssa→opt→regalloc→isel→encode + safe-reject) | Done | One-time preparation, deterministic layout and checked reference rewriting |
| Historical relocation-only round-trip (169 functions) | Archived | `b29b83b`; the verbatim API/CLI path is removed |
| No-transform SSA round-trip (coverage = SSA-lowered) | ✅ Verified, honest metric | Coverage counts **only** SSA-lowered functions; verbatim relocation (a "weak move") is now reported as a reject with its real reason, not as coverage. `sw`/`sw2`/`sw3`/`target`/`flag`/`hex` reproduce exact output, `kamy verify` PASS (deterministic). kernel32.dll: **430/1751 (~24.5%) via SSA**; rejects dominated by `RegisterPressure 848` (zero-spill D5 + over-approx call args D14), `SEHComplex 395`, `UnsupportedInstruction 39`. Full taxonomy in `kamy-core::RejectionReason`. |
| SSA backend ABI + control-flow correctness (D31) | ✅ Done | The backend had never emitted correct code. Fixed across `08ff18c`/`23a792e`/`cd61f2a`/`167cc98`: multi-block phi destruction (sequentialized edge copies + critical-edge landing blocks) and branch resolution (sentinel block IPs so iced `BlockEncoder` links intra-function jumps); subtract-comparison flags lower to `cmp a,b` (was `test a,a`); I8 flag values get distinct registers (was hard-pinned to RAX, so compound conditions clobbered each other); deterministic interval ordering; non-pinned values avoid any register pinned by an overlapping interval (replacing an unsound mid-life eviction copy that clobbered live values such as the frame pointer); RIP-relative data; indirect calls; direct tail calls (`IrTerminator::Tail` with ABI arg liveness + frame teardown before the jmp); `CallIndirect` as a DCE root. Add- and constant-shift-based condition flags consumed by a branch/`setcc` lower by re-executing the op into a reserved R11 scratch (`mov r11,a; add r11,b; jcc`). **Residual conservative relocations (sound, D22):** self-recursive functions (lowered frame too large — needs D5 stack-frame reconstruction), functions branching on a variable-count shift flag (reproducing it needs CL, which the allocator does not model), unmodeled (NativeInline) RIP-relative instructions, indirect / switch `Unknown` terminators (indirect tail jmps included), and genuine >15-register pressure (D5 zero-spill, reducible with the D14 cc DB). |
| MBA pass (add/sub/xor rules, D13 config shape) | Done | `1cfc37b` |
| MBA probability fix | Done | `fa6b941` |
| MBA visible output | ✅ Done | Exposed two real lowering bugs (now fixed): constant shifts routed the count through `CL`, clobbering a live RCX the allocator does not model — now emit the immediate-form shift (`shl r,imm`); and `emit_void` hardcoded I64 store width, truncating sub-qword stores — now threads the real operand width. `sw`/`sw2`/`sw3`/`target` with MBA (`probability:100`): exit matches original, `kamy verify` PASS (200 runs), output deterministic, bytes differ from `probability:0`. **94/203 via SSA** on `sw` (was a deterministic crash before the fix). |
| Win32metadata calling-convention DB (D14) | ✅ Done | Embedded 18.2k-fn table generated offline from `Windows.Win32.winmd` (`tools/win32cc-gen`, workspace-excluded) + curated CRT supplement; `MapCallConv` resolves import slots (`call [rip+slot]`) and single-block import thunks to precise per-arg GPR/XMM classes + return class; variadic/aggregate-return omitted (sound). Cross-checked vs IDA 9.4 til (1168 common names, 0 float/vararg errors, 19 diffs all on legacy fns where metadata is authoritative). Corpus 21/23, RegisterPressure 3576→3531, SSA-lowered 2113→2158. |
| Historical pressure-aware transform budgeting (D28) | Superseded by H2 | The intensity knob remains; pressure-driven retry/reduction is removed by the final H2 cutover below. |
| Actual-body .pdata/UNWIND_INFO reconstruction (D31/#20) | Done for supported plain functions | Per-state v2 ranges describe body stack allocation and GPR/XMM saves; handler/scoped or unprovable states stay resident |
| Differential self-test harness (kamy-verify) | ✅ Done | `kamy verify --original X --protected Y`: exit + stdout diff over N seeded runs. The Phase 2 shipping gate. |
| 8/16-bit register write semantics | ✅ Done | `write_gpr_sub64`: 8/16-bit GPR writes merge into the live register (`(old & ~mask) | zext`) rather than zero-extending; only 32-bit zero-extends (x86). Fixed a latent partial-register miscompile (`mov al,X` dropped the destination's upper bits). `b3b326a`. |
| Callee-side argument inference (own functions) | ✅ Done | Leaf-only read-before-write liveness over the Win64 argument registers narrows signatures for the target's unnamed functions (`kamy-analysis::infer_signature`); sound-by-construction — tail-forwarding/indirect exits force all args live-out, ambiguous/non-contiguous prefixes bail to the four-arg default. +25 SSA-lowered / −26 RegisterPressure over the partial-register-fix baseline; corpus 21/23. `214e2ee`. |

### Historical backend bugs and repairs

These entries retain their original measurements. H2 below supersedes the
zero-spill pools and volatile-pinned live-across-call limitation in entries 3
and 7; their old counts are not current rejection totals.

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
   Actual-body unwind reconstruction now emits each GPR/XMM restore from the
   fixed frame base. Full unscaled FAR offsets cover unaligned saved-XMM slots;
   this is verified with Windows `RtlVirtualUnwind`, without a frame pointer.
   A fixture retaining eight vectors across a call previously lowered into
   XMM6–XMM13 and passed differential verification.
4. **Return-address push is materialized.** `Store(rsp, const_return_addr)` before
   Call could be folded into the Call node. Optimization, not correctness.
5. ✅ **FIXED — Over-approximated call args (D14).** `Win64Default` passed four
   args for every call. `MapCallConv` now resolves named imports (Win32metadata
   DB + curated CRT) to precise register-arg counts and per-arg GPR/XMM class;
   unresolved targets keep the sound four-arg default. Own-function signatures
   await PDB ingest (#28).
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
8. ✅ **FIXED — SSA construction dropped the loop back-edge phi argument (#24).**
   When a loop header was processed before its back-edge (body) predecessor in
   RPO, the header phi captured the body's unresolved entry `Undef` placeholder;
   resolving the body later rewrote only the body block, so the header phi (in a
   *different* block) kept the dead `Undef` → iteration 2+ dereferenced a garbage
   loop-invariant pointer (AV). Fix (`kamy-lift/src/ssa.rs`): placeholder
   resolution now threads the back-edge phi arg across *all* blocks, not just the
   resolving one. Regression test lowers the exact `strnlen` loop and asserts no
   `Undef` reaches a phi arg. Flipped `gui_msgbox` to PASS.
9. ✅ **FIXED — linear-scan liveness truncated loop-crossing values (#24).** Live
   ranges came from a value's *syntactic* last use over a DFS block order, so a
   value live across a loop back-edge — a loop-carried phi value or a
   loop-invariant value used inside the loop — was freed at its textually-last use
   and its register reused by a later-ordered in-loop block, clobbering it
   mid-loop (corrupted the ucrt `write_integer` hex nibble loop: wrong digits +
   non-hex bytes). Fix (`kamy-codegen/src/regalloc.rs`): liveness is a real
   backward SSA dataflow to a fixpoint and each interval is the convex hull of
   every point where the value is live, so loop-crossing values stay reserved for
   the whole loop. Sound regardless of block order (collapsing holes only
   over-reserves). Regression test asserts a loop-invariant value stays live
   through the latch terminator. Took the runnable corpus 3/22 → 11/22.

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
| Per-function config profiles + symbol matching | ✅ Done | PDB function naming (`kamy-pdb`: RVA→name from public + procedure symbols; `sub_<rva>` fallback) wired into `analyze`. `target::resolve_targets` maps config selectors `!Name`/`!Pattern`/`!Address`/`!Group`/`!TopXref N` → function RVAs via PDB/export/`sub_` labels (`*`/`?` glob), with reusable `groups:` (cycle-guarded) and high-xref targeting; previewable with `analyze --select`. `protect --profile` applies each profile's passes only to its selected functions (empty `symbols:` = whole module; first profile to claim a function wins) and reports per-profile counts + per-function assignments. Verified on `console_fibmix` (`!TopXref 5` → exactly the 5 hottest; corpus 21/23, no regression). |
| Jump table recovery & lowering (D24) | Layers 0 + 2 (detect + **tableless ladder**) done | Layer 0: `jmp [rip+slot]` classified at discovery; link skips import thunks, reports in-image static-ptr as `ResolvableIndirect`. Layer 2 detect: per-function use-def DAG + petgraph VF2 (research.md §10.5) recovers the table (bound-or-reject following index copies, in-range cross-check) and tags `Terminator::Switch`. **Lowering:** the lifter expands the dispatch into a tableless compare ladder (`index==k → entries[k]`); the function SSA-lowers like any other and **no table survives** (matching CodeDefender). Verbatim table-retarget (`.kamytb`, `build_switch_body`, `RecoverableSwitch`) removed. Runtime-verified by `console_jtable`. |
| Function cross-reference / call-graph map (#18) | ✅ Done | `kamy-analysis::build_call_graph`: direct call edges + per-function incoming call-site counts; `top_xref(n)` yields the high-xref set. Surfaced in `analyze` (top references + per-function xref column). Enables high-xref targeting for #29. `4bebf5c`. |

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
binary — protected through the SSA backend (`protect_with_transforms` + identity
transform, so a miscompile surfaces as a crash) — against a committed golden
record blessed from the original, and reports SSA lift/lower coverage beside the
verdict. Open tool, not a CI gate (D33).

| Member | Toolchain | Oracle | verify | SSA / reloc / reject | coverage |
|--------|-----------|--------|--------|----------------------|----------|
| console_cfg | msvc (cl) | stdio | ❌ FAIL | 145 / 0 / 383 | 145/528 (27.5%) |
| console_cfg_lto | msvc (cl) | stdio | ❌ FAIL | 145 / 0 / 383 | 145/528 (27.5%) |
| console_eh | msvc (cl) | stdio | ❌ FAIL | 143 / 0 / 381 | 143/524 (27.3%) |
| console_fibmix | rustc | stdio | ✅ PASS | 37 / 1 / 311 | 37/349 (10.6%) |
| console_fp | msvc (cl) | stdio | ✅ PASS | 131 / 0 / 352 | 131/483 (27.1%) |
| console_jtable | rustc | stdio | ✅ PASS | 38 / 0 / 311 | 38/349 (10.9%) |
| console_seh | msvc (cl) | stdio | ✅ PASS | 132 / 0 / 348 | 132/480 (27.5%) |
| console_sse | msvc (cl) | stdio | ✅ PASS | 130 / 0 / 348 | 130/478 (27.2%) |
| console_sse_lto | msvc (cl) | stdio | ✅ PASS | 130 / 0 / 348 | 130/478 (27.2%) |
| console_sse_minsize | msvc (cl) | stdio | ✅ PASS | 130 / 0 / 348 | 130/478 (27.2%) |
| console_sse_od | msvc (cl) | stdio | ✅ PASS | 132 / 0 / 347 | 132/479 (27.6%) |
| console_switch | msvc (cl) | stdio | ✅ PASS | 130 / 0 / 348 | 130/478 (27.2%) |
| console_tls | msvc (cl) | stdio | ✅ PASS | 130 / 0 / 348 | 130/478 (27.2%) |
| dll_abi | msvc (cl) | loader | ❌ FAIL | 111 / 0 / 253 | 111/364 (30.5%) |
| dll_adx | clang-cl | loader | ❌ FAIL | 106 / 0 / 261 | 106/367 (28.9%) |
| dll_asm | clang-cl | loader | ❌ FAIL | 107 / 0 / 260 | 107/367 (29.2%) |
| dll_atomic | msvc (cl) | loader | ❌ FAIL | 108 / 0 / 254 | 108/362 (29.8%) |
| dll_bmi1 | clang-cl | loader | ❌ FAIL | 110 / 0 / 260 | 110/370 (29.7%) |
| dll_bmi2 | msvc (cl) | loader | ❌ FAIL | 111 / 0 / 252 | 111/363 (30.6%) |
| dll_bmi2_minsize | msvc (cl) | loader | ❌ FAIL | 111 / 0 / 252 | 111/363 (30.6%) |
| dll_strutil | msvc (cl) | loader | ❌ FAIL | 110 / 0 / 252 | 110/362 (30.4%) |
| gui_msgbox | msvc (cl) | gui link-shim trace | ✅ PASS | 141 / 0 / 384 | 141/525 (26.9%) |
| kernel32 (vendored) | prebuilt | loader | ✅ PASS | 285 / 2 / 1422 | 285/1709 (16.7%) |

23 members: 13 console (rustc + msvc breadth — CFG, LTO, EH, SEH, scalar/packed
SSE, switch, a jump-table ladder, TLS, and an /O2–/O1–/Od opt spread), 8 pure-export DLLs (ABI, ADX,
BMI1/BMI2, atomics, inline asm, strutil), the gui link-shim, and vendored
kernel32. The clang-cl members (`dll_adx`, `dll_asm`, `dll_bmi1`) carry GNU
extended inline asm and explicit BMI/ADX opcodes; their `-mbmi`/`-mbmi2`/`-madx`
target features and per-member linker flags (`/guard:cf`, `/LTCG`) flow through
`meta.yml` (`flags`, `link_flags`).

- gui trace comes from a build-time winapi link-shim (no DLL injection):
  `MessageBoxW|hello world`, `MessageBoxW|second`.
- dll members run under a loader that maps a uniquely-named copy — defeating the
  KnownDLLs short-circuit so kernel32's real bytes execute — and call curated
  pure exports (`MulDiv(6,7,3)=14`, `lstrlenW=5`, `kamy_fnv("abc")=440920331`).
- Coverage = SSA-lowered / total; **relocated and rejected are both not-covered**.
  Verbatim relocation is banned — SSA failures are rejected in place. TOTAL
  2113/11388 (18.6%) — down from 25.3% because the call-argument ABI pin and the
  C++-EH-runtime / `/GS` rejects trade coverage for soundness (D22: correctness
  first; recovery tracked under #15/#31). Rejections by reason, descending:

  | reason | count |
  |--------|-------|
  | SEHComplex | 3992 |
  | RegisterPressure | 3576 |
  | UnsupportedInstruction | 714 |
  | LiftFailure | 557 |
  | CallerFrameAccess | 218 |
  | BadIndirectBranch | 101 |
  | ResolvableIndirect | 72 |
  | NoThunkSpace | 35 |
  | SelfRecursive | 10 |

  `SEHComplex` now leads: it also carries the C++-EH-runtime cluster left verbatim
  so exception dispatch stays correct. `RegisterPressure` follows (recovery tracked
  in #15). `CallerFrameAccess` and `fs/gs` ship as sound conservative rejects (D22)
  → #15 and #26, both `known-limitation`.
- **21/23 PASS.** `#23` (the residual corpus miscompiles the #24 fix unmasked) is
  resolved down to the unimplemented CFG/EH phase. Fixes, each a standalone commit:
  - **DLL teardown (8 `dll_*`) — call-argument ABI pin.** The root cause was *not*
    pointer materialization: a lowered CRT cleanup called `FlsFree(dwTlsIndex)`, but
    a call argument whose value crossed a block boundary was pinned on the pre-SSA
    block-entry placeholder; SSA resolution rewrote the call's arg to the real value
    and orphaned the pin, so the allocator parked the index in R11 and left `-1`
    (the compare constant) in RCX → `FlsFree(-1)`. The FLS index then stayed
    registered and its callback dangled into the unmapped module at process exit
    (`0xC0000005`). SSA now transfers the pin to the resolved value. Flipped 6
    `dll_*` directly; a general call-arg soundness fix.
  - **#8 NativeInline operand pinning (`dll_asm`).** Read/write operands of a raw
    re-emitted instruction are now pinned to their physical registers (copy-out on
    aliasing; write regs reserved across the native point). `#8` closed.
  - **`dll_bmi1` `bmi1_tzcnt`.** A NativeInline `adc` reads the carry flag, a
    dependency SSA does not thread, so the `cmp` producer was DCE'd and `tzcnt` saw
    garbage (returned 0). NativeInline that reads `rflags` now rejects (verbatim).
  - **`dll_abi` — corpus-oracle bug.** The loader's call shim dropped every argument
    past the fifth, so `abi_many`'s sixth parameter read uninitialized stack and the
    member was non-deterministic; its `79` golden was blessed from that garbage. The
    loader now passes all six; golden re-blessed to `91`.
  - **`console_eh` — C++ exception runtime.** A C++ throw dispatches through the
    `__CxxFrameHandler` personality and the functions it reaches (FindHandler,
    FH4::TryBlockMap4, catch/continuation helpers); relocating any of them
    miscompiles handler lookup → unhandled → fast-fail. The personality cluster is
    now left verbatim when user code dispatches through it (non-EH images keep full
    coverage). A `/GS` cookie-stamp reject (`xor r,rsp`) also landed.
- **2 FAIL remain — `console_cfg`, `console_cfg_lto`** (`/EHsc` **+ `/guard:cf`**).
  `console_eh` (same source, no CFG) passes, so the residual is the Control-Flow-
  Guard + C++ EH dispatch path: a layout-sensitive miscompile that needs CFG-table
  / unwind reconstruction. That is a later phase (D31 / CFG), not yet built; these
  stay rejected-incomplete until then.
- Negative-tested: a tampered golden makes `verify` exit non-zero and flag the
  diverging member (the oracle is not a tautology).
- `corpus build`/`bless` need the toolchains (cl via `vcvars64.bat`, rustc, and
  `clang-cl` on `PATH` for the asm/BMI/ADX members); `corpus verify` consumes the
  published originals + goldens and needs no compiler (D34).
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
| Runnable corpus (#7): 23 members (console/gui/dll/kernel32) | 🔶 21/23 PASS | #23 residual miscompiles fixed: cross-block call-arg ABI pin (DLL teardown, 8 dll_*), #8 NativeInline operand pinning (dll_asm), rflags-reader reject (dll_bmi1 tzcnt), loader six-arg fix + re-blessed dll_abi golden, and leaving the C++ EH runtime verbatim (console_eh). Remaining 2 FAIL (console_cfg/cfg_lto) are `/EHsc`+`/guard:cf`; the CFG+EH dispatch path needs CFG-table/unwind reconstruction (D31/CFG phase, not built). |

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

**Tableless compare-ladder lowering (supersedes Phase B retarget).** A recovered
switch is no longer relocated verbatim with a rebuilt table — verbatim movement
is banned, so moving a table-carrying body without lowering it violated that
rule. Instead the lifter expands `Terminator::Switch` into a compare ladder:
each rung tests `index == k` (falling through to `entries[k]`, continuing on the
taken edge to the next rung so the DFS block order keeps rungs contiguous and the
index's live range tight), the final rung falls through to `entries[last]`, and
the dispatch tail (table load + indirect `jmp`) is dropped. **No table survives**
in the output — matching CodeDefender (docs/code_defender.md §"Switch /
jump-table handling"). The function then lowers through SSA like any other; if it
carries an orthogonal blocker (SEH, register pressure) it rejects in place. The
`.kamytb` section, `build_switch_body`, table re-emission/retarget, and
`RejectionReason::RecoverableSwitch` are all **deleted** (clean cutover). The
recovery also now follows `mov index, src` register copies when locating the
index bound (`cmp ecx,15` before `mov eax,ecx; …[rax*4]`), so LLVM/rustc dense
switches whose bound renames the index are recovered.

Runtime-verified by `console_jtable` (new corpus member): a `#[inline(never)]`
16-case `vm` switch recovers, lowers to the ladder (`regalloc` OK), and reproduces
its accumulator over 20,000 iterations (`relocated` = 0 corpus-wide — verbatim
movement is gone). The computed-`jmp`/pad obfuscation CodeDefender layers on top
is a separate Phase-4 transform.

## Relocation rebuild — pre-D40 implementation snapshot (#17, D37–D39)

The supported input is x86-64 PE32+; x86/PE32 is out of scope.

Host reference analysis (#18) now records per-function incoming/outgoing
references and explicit uncertainty for branches, RIP-relative operands,
relocated pointers, recovered switches, unwind, exports, TLS, LoadConfig and
debug metadata. Ambiguous ownership, code-as-data, interior targets, untracked
addresses and unsupported reference consumers keep the target resident.
`analyze` reports the sets and deterministic unresolved-reference rows.
Import/forwarder thunks remain excluded from protection-target accounting.

The corpus exercises flagged volatile metadata, numeric LTCG/SPGO signatures,
extended guard-table strides, ordinal-only exports and x64 dynamic function
overrides. Unrecognized encoded metadata still fails closed; this is not a
claim of complete blind recovery of dynamically computed addresses.

The host reference cutover (#19/#20/#30/#22/#33/#35) removes entry thunks,
`NoThunkSpace`, and the legacy verbatim API/CLI route. Both identity flags use
the same SSA path. Resident callers' reference operands are rewritten; selected
bodies move, and unprovable targets remain resident. Absolute pointers, EAT,
TLS/LoadConfig references and loader fixups follow the moved map. Debug records
are rebuilt, including POGO contributions, without treating a range start as a
function pointer.

`kamy-seh` reconstructs the actual encoded CFG's stack/nonvolatile states.
Version 2 ranges avoid v1's incorrect epilogue scan across fragment jumps;
Windows `RtlVirtualUnwind` confirms branch, saved-XMM and empty-frame behavior.
Unsupported handler/scoped or dynamic frames remain rejected. CFG is explicitly
non-enforcing (`GuardFlags=0x100` when instrumented), with cleared guard tables,
valid cookie targets and relocated check/dispatch slots.

Verified: formatting, clippy with denied warnings, workspace/all-target build,
and **225 tests** pass. Differential corpus: **23/23 PASS**, **1314/11202
SSA-lowered (11.7%)**, zero verbatim relocations and zero `NoThunkSpace` rejects.
The pre-change executable baseline was 21/23 PASS and 2100 SSA-lowered; coverage
remains conservative, and the previously failing throw helpers stay resident.
This does not claim their underlying miscompile is repaired.

A throwaway x64 DLL proves direct moved entry/EAT, a rebased `.reloc`-backed
function pointer, a rewritten resident direct caller, runtime translation of an
old RVA-derived pointer, new/external-target misses, forced ASLR, and SEH unwind
through a moved frame. All four selected functions moved; the resident caller
stayed in place. Eight differential runs pass. Identity/no-transform outputs
and CSV maps are byte-identical; map-write failures surface with path context.
The probe omits unanchored linker volatile metadata; such unknown references
remain safe-rejected rather than bypassed.

Image rebuilding (#27) repacks raw storage without sliding resident RVAs or
changing their section ordinals. Imports retain stable IAT slots while fresh
descriptors, lookup tables and names share read-only metadata with xdata,
Debug and BaseReloc; the fresh Exception table stays separate. Dead code tails
shrink only with a proven live-data/reference boundary. Retired Exception slots
are eligible for executable helpers only when their entire ownership and lack
of external consumers are proven. Interior retired bodies use complete NOPs,
not entry thunks or an INT3 flood.

The forced-ASLR DLL probe retains its resident caller and shrinks `.text` from
122 to 49 virtual bytes; moved entry/EAT, absolute pointers, indirect translation
and SEH still execute correctly. Blank and `.cache` section-name profile builds
each pass eight differential runs of `console_cfg`. The full corpus has no
coverage delta against the thunk-free cutover baseline. Optional naming (#34)
does not affect correctness or enable injection.

A second forced-ASLR probe recycles its old 168-byte Exception slot as live RX
`.text` translation helpers with 51 valid fresh runtime ranges. Its retired
original `.text` has no raw bytes but retains one virtual byte to preserve
mapped-section adjacency. Eight differential runs pass, including SEH through
the moved frame. A portable multi-page regression preserves rounded virtual
coverage while removing dead raw bytes.

Configurable Rust-only SDK/plugin injection (#32, D39) is implemented.
`kamy plugin build` compiles a freestanding Cargo `staticlib` with native fat
LTO, retains compiler symbol/relocation provenance, and packages a specialized
DLL with unmerged data directories. `kamy-sdk` supplies the Win64 callback,
aborting panic handler and optional linker-filled init-table bounds. There is
no C/C++ SDK or runtime plugin-DLL loading.

Enabled YAML profiles select an ordered list of named artifacts and either
inline or init-table entry sequencing. Paths resolve relative to the profile;
`plugin::symbol` selectors use the existing transform pipeline. Every module
function must pass SSA/codegen and unwind reconstruction; an unsupported or
resource-exceeding function fails injection rather than being omitted or relocated
verbatim. Historically the combined bounds-check/counter probe exercised a strict
`RegisterPressure` failure; H2 below records its intact identity/MBA execution.
Injection remains off by default, requires an original entry point, and rejects
kernel images before discovery.

Authored references retain compiler symbol bases and signed addends rather
than guessing pointers from constants. Portable regressions and real Rust
builds cover `__ImageBase + RVA`, local data interiors and LLVM's negative
REL32 addend for trailing immediates. Compiler provenance is consumed and
stripped from the protected output; numeric literals are not rebased.

Runtime acceptance uses Rust-only plugin and EXE/DLL fixtures:
- Two ordered callbacks produce `trace=12` in both entry modes, with an MBA
  profile selecting both authored functions.
- Forced-ASLR DLL loads preserve the exact instance/reason/reserved arguments
  and the original `DllMain` TRUE return.
- `RtlLookupFunctionEntry` and `RtlVirtualUnwind` validate the generated loader's
  72-byte frame and recover its caller under forced ASLR, including pure-PIC
  inline output with a zero BaseReloc directory and no unnecessary table.
- EXE and DLL bounds callbacks read the linker-filled table slots correctly;
  the DLL case runs under forced ASLR.
- A non-inlined Rust dependency function is included by native LTO, lowered
  with its caller and executed after linking.
- Nonzero callback status stops both EXE/DLL entry modes with `0xc0000409`;
  original startup is not reached. A disabled missing-plugin path is ignored.
- An injected integrity callback preserves `console_tls` behavior across eight
  differential runs. Import names/IAT RVAs, runtime ranges and stripped module
  provenance are checked on both ordered EXE/DLL outputs.

Module imports, module TLS/PE export directories, language-handler unwind,
interior-code pointers and unsupported instruction/operand forms remain explicit
errors. Exact authored reference coverage does not waive instruction, explicit
ABI, frame or unwind support. D40 supersedes the former zero-spill policy;
pressure rejection/reduced intensity were pre-H2 limitations, superseded by the
memory-backed cutover below. Enforcing module CFG and the vendor's unobserved
extras remain outside this epic's gates.

## D40 repair campaign — handoff-1 contracts and evidence

**Handoff 1 complete.** The integration owner observed all four workspace gates
green (**311 tests, 41 suites**), final identity corpus **23/23 PASS**, and the
freshly rebuilt **full** SDK structural/runtime matrix `sdk-rebuild=full PASS`.
This completes the symbol/reference/ABI/single-rebuild milestone, not handoffs
2–4. Current evidence follows the historical intermediate snapshots below.

Policy milestone `5ef9b46` records D40 before implementation. The integration
owner reports these gates green for that policy milestone:

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo build --workspace --all-targets
cargo test --workspace
```

The supplied test count is **225**. These results establish the policy baseline,
not verification of the later symbol/ABI/link/schema changes.

The supplied pre-cutover identity baseline is **23/23 PASS**, **1,314/11,202
SSA-lowered**, and **9,888 rejected**: 3,846 `SEHComplex`, 3,323
`SymbolizationUncertain`, 1,740 `RegisterPressure`, 557 `LiftFailure`, 209
`UnsupportedInstruction`, 101 `BadIndirectBranch`, 64 `CallerFrameAccess`, 32
`ResolvableIndirect`, 12 `InvalidReference`, 2 `EhNoBucketCreation`, and 2
`SelfRecursive`. This is the comparison population, not a post-cutover result.
Execution verdict, selected/eligible/lowered/actually transformed counts,
effective intensity and rejection transitions MUST be reported separately.
Population additions/removals MUST NOT be counted as recovered coverage.

D40's ordered scope remains binding: handoff 1 owns unified symbols, authored
ABI contracts and one rebuild; handoff 2 owns concrete frames/memory-backed
lowering; handoff 3 owns compiled Rust startup, ordinary imports and Rust `std`
with `panic=abort`; handoff 4 owns whole-image virtual compaction. The current
freestanding SDK workflow and generated loader are limitations, not the target.
The earlier callback, ASLR and unwind observations above are historical evidence
for the old implementation, not runtime acceptance of the new contracts.

The implementation owners supplied the handoff-1 interfaces documented in
[architecture.md](architecture.md): source-qualified `SymbolId`, shared signed
`SymbolicExpression`/`Reference` fields, exact authored operand annotations,
explicit `FnSignature`/`AbiValue`, the single `kamy_link::protect` entry and
original-host `PeEdits` plan, generated helper placements and directory
ownership/file-coordinate reports. These are interface records, not acceptance
results. Authored artifacts use KAMYMOD version 2; public maps use CSV
`kamy-debug-map,2`; structural JSON reports use `kamy-link-report` version 1.
Old artifacts MUST be rebuilt and old map consumers migrated, without numeric
module namespaces or compatibility aliases.

The supplied producer contract uses Rust post-LTO IR and matching LLVM 22.1.2
full native emission with machine-state capture in the same invocation, not
serialized MIR resumption. The known SDK callback boundary is validated
explicitly; unused machine inputs do not prove arbitrary missing argument
locations. Unsupported internal ABI records fail closed. This records no new
runtime ABI claim. Current tool discovery and supported/rejected settings are
specified in [tooling.md](tooling.md).

Profile-plus-identity retains configured injection/naming and suppresses semantic
passes. Supported MBA requests remain ordered; unsupported passes/settings and
profile/RVA-selector conflicts are explicit errors. Effective intensity remains
separate from requested transformation until handoff 2 removes pressure retries.
`tests/sdk-rebuild` retains the original combined pressure witness intact; its
presence is not recovery or execution evidence. Later handoffs MUST reuse these
contracts and portable fixtures rather than introduce another ABI, namespace,
loader-only backend or rebuild stage.

### Initial handoff-1 union gates (before boundary repair)

The integration owner reports these commands green on the implementation union:

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo build --workspace --all-targets
cargo test --workspace
```

Result: **275 tests passed across 40 suites**. The workspace language-server
`cargo check` diagnostics were also clean. This snapshot precedes the subsequent
generic ABI-pin boundary repair and native-oracle correction. It is not the
final gate result for those later changes or a runtime oracle.

### Initial post-cutover identity corpus (before boundary repair)

The integration owner ran the rebuilt debug CLI with this invocation (local
paths are parameterized):

```sh
target/debug/kamy.exe -q corpus verify --corpus <corpus-checkout> --keep --baseline <before.yml> --write-baseline <after.yml>
```

Result: **23/23 PASS**, **1,314/11,202 SSA-lowered**, **9,888 rejected**.
Every member's lowered count and rejection-reason totals match the pre-cutover
baseline, including **1,740 `RegisterPressure`** and **64 `CallerFrameAccess`**.
No aggregate recovery or population-denominator change is claimed. Source-level
per-function transition comparison is a separate measurement, not implied by
matching totals.

The new report axes are **12,848 selected**, **3,343 eligible**, **0 actually
transformed**, and `actual_intensity: {"0": 1314}`. Selected includes discovered
import/forwarder seeds and is not the 11,202-function coverage denominator.
The old YAML lacked these axes; a printed zero-to-new-value delta is a schema
addition, not recovered coverage or additional protection. This run exercises
identity behavior, not MBA or authored-module runtime acceptance.

### Historical boundary-repair regression — repaired before acceptance

The integration owner subsequently exercised a CLI containing the generic
ABI-pin repair, before the NativeInline RIP-provenance correction. That
intermediate identity corpus was **11/23 PASS**, **1,697/11,202 lowered** and
**9,505 rejected**, including 971 `RegisterPressure`, 449 `CallerFrameAccess`
and 3 `EhNoBucketCreation`. That intermediate lowered increase was not accepted
coverage: execution regressed. Subsequent headless bisection isolated RVA
`0x96b4`; real implicit arithmetic and boundary/provenance repairs preceded the
green final corpus and actually lowered culprit execution recorded below. No
blanket reject, population reduction or protected-output re-blessing was used
as the acceptance substitute.

### Repaired-union workspace gates

The integration owner reports the repaired union, including initialized bound
storage, accurate rejection dispatch and fast-fail outcome classification,
green under:

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo build --workspace --all-targets
cargo test --workspace
```

Final result: **311 tests passed across 41 suites**, with clean workspace
language-server `cargo check` diagnostics after the storage repair. The earlier
308-test gate preceded that repair. Separate fresh corpus and full SDK runtime
results below supply the execution evidence; workspace tests alone do not.

### Repaired identity corpus and isolated culprit execution

The integration owner reports the repaired CLI's identity corpus **23/23 PASS**,
**1,721/11,202 SSA-lowered (15.4%)**, and **9,481 rejected**. The reported
population remains **11,202**; lowering increased by **407** against the
1,314-function baseline. Identity reports **0 actually transformed**. This is
backend coverage, not additional MBA protection or memory-backed allocation.

| Rejection reason | Repaired count |
|---|---:|
| SEHComplex | 3,846 |
| SymbolizationUncertain | 3,323 |
| RegisterPressure | 869 |
| LiftFailure | 557 |
| CallerFrameAccess | 488 |
| UnsupportedInstruction | 247 |
| BadIndirectBranch | 101 |
| ResolvableIndirect | 32 |
| InvalidReference | 12 |
| EhNoBucketCreation | 3 |
| SelfRecursive | 3 |

The integration owner also asserted that isolated host culprit RVA `0x96b4`
actually lowered, then observed **four-vector native differential verification
PASS**. This is execution of the repaired body, not success through residency.
The integration owner's exact source-function comparison uses saved baseline
mover maps/rejections against the new structured link reports for all 23 same
inputs: **11,202 → 11,202**, **0 added**, **0 removed**. It records **421
recovered**, **14 lost**, net **+407** lowered functions. The 14 lost functions
MUST NOT be concealed by the net improvement.

| Before | After | Functions |
|---|---|---:|
| SSA-lowered | RegisterPressure | 9 |
| RegisterPressure | SSA-lowered | 414 |
| RegisterPressure | CallerFrameAccess | 413 |
| RegisterPressure | UnsupportedInstruction | 55 |
| SSA-lowered | UnsupportedInstruction | 3 |
| SSA-lowered | CallerFrameAccess | 2 |
| UnsupportedInstruction | RegisterPressure | 3 |
| UnsupportedInstruction | SSA-lowered | 4 |
| CallerFrameAccess | SSA-lowered | 3 |
| UnsupportedInstruction | CallerFrameAccess | 12 |
| RegisterPressure | EhNoBucketCreation | 1 |
| UnsupportedInstruction | SelfRecursive | 1 |

New physical-boundary constraints, the existing frame guard and explicit
unmodeled native-flag checks explain rejection classes; they do not implement
the pressure/frame guarantee assigned to handoff 2. The comparison preserves
every source function rather than changing the population to improve coverage.

### Final full SDK structural/runtime matrix

The integration owner rebuilt both hosts and regenerated **all 11 real Rust
module artifacts** with the initialized linker-bound storage contract, then ran
the full harness. All three stages exited zero; the final output was
`sdk-rebuild=full PASS`. The exercised commands were the following, with local
tool/library paths supplied as arguments rather than committed dependencies:

```sh
target/debug/sdk-rebuild.exe build --out target/sdk-rebuild --kamy target/debug/kamy.exe --cargo cargo --rustc rustc --linker <lld-link.exe> --llvm-tools <matching-LLVM-tools-directory> --lib-dirs <semicolon-separated-library-directories> --scope full
target/debug/sdk-rebuild.exe produce --out target/sdk-rebuild --kamy target/debug/kamy.exe --cargo cargo --rustc rustc --linker <lld-link.exe> --llvm-tools <matching-LLVM-tools-directory> --lib-dirs <semicolon-separated-library-directories> --scope full
target/debug/sdk-rebuild.exe run --out target/sdk-rebuild --kamy target/debug/kamy.exe --cargo cargo --rustc rustc --linker <lld-link.exe> --llvm-tools <matching-LLVM-tools-directory> --lib-dirs <semicolon-separated-library-directories> --scope full
```

- **EXE/DLL × inline/init-table:** ordered callbacks, ABI, bounds and fast-fail
  scenarios pass. DLL checks preserve exact entry arguments and TRUE return;
  the replay oracle produces `1212`. Forced ASLR passes throughout the matrix.
- **Identity versus transformation:** profile-plus-identity preserves injection
  and naming, with callback-module lowered counts `[1,1]` and transformed counts
  `[0,0]`. The ordered two-MBA-entry profile lowers `[1,1]` and actually
  transforms `[1,1]`; selector visitation alone is not the oracle.
- **Actual ABI calls:** the scalar Float64 XMM0 argument/return contract is
  validated, with a real source call `0x104b → 0x1160` and a final decoded call
  to its symbol's actual placement. Runtime ABI outputs are `abi=true`, including
  the mixed integer/floating and aggregate cases in the fixture. This does not
  claim runtime coverage for every represented ABI type or f32.
- **BSS and permissions:** all four ABI outputs report `bss_virtual_ranges=1`;
  the 8 KiB virtual tail stays writable/nonexecuting without file-backed zero
  extension. Runtime zero-initialization and read/write checks pass. The earlier
  real BSS regression was repaired through initialized native bound cells and
  nonextending field writes, not by weakening the oracle or changing goldens.
- **Native Windows unwind:** independently constructed machine-state probes
  pass for a 96-byte module callback frame, an 8-byte scalar frame and the
  generated loader's 72-byte frame. Poisoned nonvolatile GPR/XMM state is
  restored. These probes cover selected logical post-prologue PCs; structural
  checks cover all Exception ranges, not every-fragment runtime execution.
- **Intact pressure witness:** the original combined bounds-check/counter
  callback actually lowers and executes with `trace=12` and span **24**. It is
  not split, and no `EXPECTED_LIMITATION` fallback is taken. This repairs that
  witness, not arbitrary pressure, concrete frames or the handoff-2 guarantee.
- **Strict configuration:** unsupported-request and flag-conflict subprocess
  cases pass, as do disabled nonexistent-plugin paths. Fast-fail checks require
  the actual `0xc0000409` fault and empty stdout; an absent normal exit alone
  cannot satisfy the oracle.
- **One active final graph:** source artifact metadata is stripped; host IAT
  counts remain **79 for EXE / 1 for DLL** in these import-free module cases.
  Final Exception/BaseReloc contributions, sorted/nonoverlapping runtime ranges,
  source-qualified maps and ownership checks pass. This is not a claim that
  future ordinary module imports must leave the host IAT unchanged.

The final post-storage-repair corpus rerun also remains **23/23 PASS**,
**1,721/11,202 lowered**, **9,481 rejected**, with the same reason totals and
exact stable-function transitions above: **421 recovered, 14 lost, 0 added,
0 removed**. No current SDK failure or pending runtime acceptance is implied
by the historical intermediate observations.

Handoff 2 consumes the documented symbolic operands, explicit ABI/call effects,
shared lowering and single-plan unwind/layout interfaces, plus the intact
pressure witness. It still owns concrete frames, memory-backed intermediates,
bounded scratch sets and removal of pressure-driven intensity reduction.
Handoff 3 consumes KAMYMOD v2, `AuthoredSource`, helper/table identities and the
same link plan; it owns compiled Rust startup, ordinary module imports, std with
`panic=abort`, runtime/TLS and process-attach-only DLL initialization. Handoff 4
extends that same ownership/reference/directory graph for whole-image virtual
compaction. None of std completeness, a compiled loader, global compaction or
general frame recovery is delivered by this milestone.

## Empty ILTCG debug records

The PE reference collector accepts type 14 (`IMAGE_DEBUG_TYPE_ILTCG`) only
when its payload size is zero. Existing RVA/file-coordinate checks remain;
unsupported nonempty payloads still fail closed. Debug rebuilding clears both
payload pointers for empty records rather than creating an end-of-blob RVA.
This implements D4/D16/D22/D37/D40 and handoff 1's section 3 directory/file-offset
contract within the existing single rebuild; no image-base or relocation model
changes are involved.

Observed verification:

- The reported `HelloWorld.exe` identity protection completes with **11
  SSA-lowered**, **0 transformed**, **32 rejected**, and no verbatim relocation.
- Native traced execution exits **0**, prints `Hello World!` followed by CRLF,
  and has no fault or timeout. Differential verification passes **32 seeded
  runs** with no exit/stdout/stderr mismatches.
- The rebuilt image reparses successfully. Its empty type-14 record has zero
  size, RVA and file pointer; nonempty debug payload RVA/file coordinates agree.
  The image base is unchanged and all **20 DIR64 fixups** target the image.
- A portable section-boundary regression failed before the emitter fix because
  an empty debug record targeted the exclusive section end. It passes after
  clearing the empty payload pointers.
- All four workspace gates pass: **314 tests, 41 suites**.
- Identity corpus: **23/23 PASS**, **1,721/11,202 SSA-lowered**, **9,481
  rejected**, **0 transformed**, **0 verbatim-relocated**; totals match the
  preceding recorded campaign result.

## D40 repair campaign — H2 concrete frames and memory-backed lowering

### Verification state and reproducible commands

**H2 remains Incomplete / Reopened; H3 waits.** Acceptance of implementation
`278f5ef81dd096e8325c06bd02ba7c88b84b0646` (`Lower SSA through concrete
memory-backed frames`), published at `d1c70e1`, was withdrawn on 2026-10-22.
All seven review findings now have a fix or scoped producer disproof in the
authoritative ledger below. The sole remaining formal H2 gate is the unavailable
original 23-member locked corpus; the available four-member run is not a substitute.
D40 policy `5ef9b46` remains binding: concrete frames, memory-backed
intermediates/flags, bounded scratch, one shared backend and one rebuild.
The [H2 completion notice](handoffs/02-memory-backed-lowering.md#completion-notice)
and [master register](handoffs/00-master.md#completion-register) track the same
state. **Repair and reaccept H2 before H3.** H1 acceptance remains unchanged.
The earlier tests, corpus and full SDK/runtime/unwind successes below remain
historical observations, not current acceptance or remote issue closure.

The following implementation-era receipts, through the pre-repair NOW evidence,
are **historical snapshots**, not the current repair result. The fresh pre-H2
baseline was **314 tests / 41 suites**, **23/23 corpus PASS**, **1,721 lowered /
9,481 rejected**. After the API cutover all four workspace gates passed:
**427 tests / 47 suites**. Current evidence is in the
[2026-10-23 repair section](#current-h2-repair-evidence--2026-10-23).

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo build --workspace --all-targets
cargo test --workspace
```

The identity corpus command is portable across checkout locations:

```sh
target/debug/kamy.exe -q corpus verify --corpus <corpus-checkout> --keep --baseline <pre-H2.yml> --write-baseline <H2.yml>
```

The observed corpus result is **23/23 PASS**, **3,173/11,202 lowered**, **8,029
rejected**, **0 actually transformed**, and **0 verbatim-relocated**. The final
fresh SDK `all --scope full` exited **0**, reporting `sdk-rebuild=full PASS` after
rebuilding the hosts and regenerating all **11 normal module artifacts** plus
the ordinary-Rust dynamic negative artifact. The SDK commands retain explicit
local tool/library parameters:

```sh
target/debug/sdk-rebuild.exe build --out <sdk-output> --kamy target/debug/kamy.exe --cargo cargo --rustc rustc --linker <lld-link.exe> --llvm-tools <matching-LLVM-tools-directory> --lib-dirs <semicolon-separated-library-directories> --scope full
target/debug/sdk-rebuild.exe produce --out <sdk-output> --kamy target/debug/kamy.exe --cargo cargo --rustc rustc --linker <lld-link.exe> --llvm-tools <matching-LLVM-tools-directory> --lib-dirs <semicolon-separated-library-directories> --scope full
target/debug/sdk-rebuild.exe run --out <sdk-output> --kamy target/debug/kamy.exe --cargo cargo --rustc rustc --linker <lld-link.exe> --llvm-tools <matching-LLVM-tools-directory> --lib-dirs <semicolon-separated-library-directories> --scope full
target/debug/sdk-rebuild.exe all --out <sdk-output> --kamy target/debug/kamy.exe --cargo cargo --rustc rustc --linker <lld-link.exe> --llvm-tools <matching-LLVM-tools-directory> --lib-dirs <semicolon-separated-library-directories> --scope full
```

The final `all` invocation repeats build, production and the full strict runtime
matrix; it is not merely a rerun against stale module artifacts. No witness was
skipped and no expected-pressure branch was used. Final combined callback frames
are **176 bytes identity / 320 bytes MBA**; ordered callback maxima are **160 /
208 bytes**. The final host-only DLL moves **1 host function** (2 eligible, with
1 `UnsupportedInstruction` remaining); the retained-original-table oracle is
still covered separately by four portable regressions, not evidence that this
final DLL has no moved host bodies.
Portable fixtures are `tests/sdk-rebuild/hosts/frame.rs`,
`tests/sdk-rebuild/src/{frame,native,probe}.rs`, and
`tests/sdk-rebuild/plugins/pressure/{original.rs,lib.rs}`. Lowering/link regression
fixtures are `crates/kamy-codegen/tests/{memory_frames,frame_coordinates}.rs`
and `crates/kamy-link/tests/{memory_frames,frame_call_alias,guard_calls}.rs`.
External temporary baseline executables and headless reports are not required
fixture dependencies.

### Stable source-function cohort, not an aggregate recovery estimate

Both snapshots contain the **same 12,848 discovered/selected identities**:
**0 added, 0 removed**. Of these, **11,202 are classified** and **1,646 skipped
identities remain unchanged**. Eligibility is **3,343 → 3,421**; it is a separate
axis, not the population denominator. Actual intensity is **0.0** for all
**1,721 → 3,173** lowered functions in this identity campaign.

The per-function comparison records **1,454 recovered**, **2 lost**, and net
**+1,452 lowered**. The complete rejection totals, including zeroed old classes:

| Rejection reason | Before H2 | After H2 |
|---|---:|---:|
| BadIndirectBranch | 101 | 101 |
| CallerFrameAccess | 488 | 0 |
| EhNoBucketCreation | 3 | 5 |
| FrameDynamic | 0 | 5 |
| InvalidReference | 12 | 12 |
| LiftFailure | 557 | 557 |
| RegisterPressure | 869 | 0 |
| ResolvableIndirect | 32 | 32 |
| SEHComplex | 3,846 | 3,846 |
| SelfRecursive | 3 | 0 |
| SymbolizationUncertain | 3,323 | 3,245 |
| UnsupportedInstruction | 247 | 226 |
| **Rejected total** | **9,481** | **8,029** |

Every changed classification row follows; unchanged identities are not omitted
from the cohort, only from this transition table.

| Before | After | Functions |
|---|---|---:|
| CallerFrameAccess | EhNoBucketCreation | 1 |
| CallerFrameAccess | FrameDynamic | 1 |
| CallerFrameAccess | SSA-lowered | 486 |
| EhNoBucketCreation | SSA-lowered | 2 |
| RegisterPressure | EhNoBucketCreation | 2 |
| RegisterPressure | FrameDynamic | 4 |
| RegisterPressure | SSA-lowered | 853 |
| RegisterPressure | UnsupportedInstruction | 10 |
| SSA-lowered | UnsupportedInstruction | 2 |
| SelfRecursive | SSA-lowered | 3 |
| SymbolizationUncertain | EhNoBucketCreation | 1 |
| SymbolizationUncertain | SSA-lowered | 68 |
| SymbolizationUncertain | UnsupportedInstruction | 9 |
| UnsupportedInstruction | SSA-lowered | 42 |

The **16 pressure-to-semantic/unwind migrations** (2 unwind, 4 dynamic-frame,
10 unsupported-instruction) are **not recovered functions**. Neither are the
other reject-to-reject migrations. Zero remaining `RegisterPressure` is not a
license to hide unproved frame or native effects under a different success label.

The two losses are `console_fibmix` source RVA **0x2650** and `console_jtable`
source RVA **0x2320**: both were lowered before and now report
`UnsupportedInstruction`. Their headless lift evidence ends in NativeInline
bytes **CD 29 (`INT 29`)**, an implicit RSP read, and a `Ret` terminator. This
observes an unsupported interrupt/termination path; it does not establish a more
specific validator cause. H5/H6 own the remaining native termination/exception
semantics. These losses are disclosed separately, not counted as pressure
recovery or as evidence of general EH completion.

### Real allocations and bounded resources

All **3,173 lowered corpus functions** use the memory-backed allocation result
and have nonzero homes; **2,132** have explicit flag homes. **15** generated
frames exceed **4,096 bytes**. The largest is **11,640 bytes**, `kernel32` source
RVA **0x67cb8**: original frame **104**, outgoing known minimum **32**, **1,793
homes** comprising **1,563 GPR**, **72 XMM**, **158 flag** homes, and **8
nonvolatile saves**. These are structural identity-lowering measurements, not
execution of every body and not MBA coverage.

Ordinary scratch pools are exactly **7 GPRs** (`RAX RCX RDX R8 R9 R10 R11`)
and **4 XMMs** (`XMM0..3`). Other explicit native/ABI registers are boundary
constraints, not extra interchangeable scratch. The checked frame-size resource
bound is **16 MiB**; arithmetic overflow and resource IDs fail explicitly.
Generated page probes cover the actual frame. The standalone fixture links and
exports the real `__chkstk` from an explicit MSVC `libcmt.lib`; recognition uses
its authoritative symbol/ABI, not guesses about anonymous helper bytes.

### Runtime and independent native unwind evidence

The standalone frame DLL's **eight exports** execute as original, protected
identity and protected ordered MBA through `kamy-run` with **forced ASLR**.
Both protected variants lower **8** exports; identity transforms **0**, MBA
actually transforms **8**. The matrix exercises six mixed register/stack
arguments, incoming homes, local/address-taken storage, pinned results,
**recursion depth 64** retaining the original **4,096-byte** object, an actual
**24 KiB** guard-page frame, and a **16 KiB** GPR/XMM-save case. Separate portable
link regression recursion reaches **96**; it is not the standalone depth-64 run.

An independent machine-CFG oracle supplies Windows `RtlLookupFunctionEntry` /
`RtlVirtualUnwind` probes over the **8 actual host placements**. Identity covers
**1,161 native PCs**, including **90 epilogue PCs**; MBA covers **1,926 native
PCs**, including **90 epilogue PCs**. Maximum actual frames are **25,208 bytes
identity / 25,640 bytes MBA**, with maximum saved **3 GPRs / 1 XMM**. These are
the standalone probes, not all corpus PCs or arbitrary handler unwinding.

The intact combined bounds/counter callback executes in **both identity and
ordered MBA**, with **trace 12 / bounds span 24**. MBA retains requested intensity
**1.0**; identity reports **0.0**. Callback lowered counts are **[1,1]**;
transformed counts are **[0,0] identity** and **[1,1] MBA**.
No split, skip, expected-pressure branch or intensity fallback substitutes for
execution. Full-scope EXE/DLL ×
inline/init-table runtime cases also pass callback ordering, Float64/aggregate
ABI, BSS, bounds, actual **0xc0000409** fast-fail, strict configuration and
disabled-path checks. This does not assert arbitrary ISA, EH or Rust-std parity.
A real ordinary Rust dynamic-inline-asm callback packages through the existing
compiler-ABI producer, then mandatory protection fails source-qualified
`FrameDynamic` with **no output file**, as the harness requires.

### Root repairs and issue/residual ownership

The backend now shares format-agnostic `FrameAnalysis`, `ConcreteFrame`,
`FrameHome` and `FrameSave` producers/consumers. Original negative-zone storage
stays LOW; intermediate homes, copy scratch and saves stay HIGH. Entry-relative
incoming homes/stack arguments/return storage retain their real coordinates.
Calls use original outgoing storage, with homes above call RSP. Unknown actual
stack arguments survive through the entire original zone; the ABI-known
`outgoing_frame_size` minimum is not guessed to be the actual argument extent.
Generated overhead is a multiple of 16, preserving original object/call alignment.

Frame logical extraction requires fully proved subtractive pointer pairs;
mixed call-returned aliases retain runtime coordinates. Proof-carrying frame
indices retain checked pre-MBA bounds. A real compiler loop exposed a dangling
XMM0-return root in `PrunePhis`; transitive cycle-safe replacement repairs the
alias graph instead of dropping the return. Constant register-index
`BT/BTS/BTR/BTC` preserve signed word offsets, full width and LOCK semantics;
unproved frame indices fail specifically. Invalid unaligned PSHUFD probes were
corrected to valid MOVDQU cases while retaining the aligned PSHUFD counterexample
and negative alignment tests. Data oracles were not weakened.

Typed UNWIND_CODE and BaseReloc scalar storage is excluded from raw-pointer scans
only after validated metadata ownership; real pointer fields remain rebound and
unknown handler data remains conservative. BaseReloc parsing accepts supported
types 0/3/10, rejects malformed/truncated data, and permits a terminal 14-byte
block because the block start, not its size, has the alignment constraint.
GuardCF dispatch's hidden RAX target comes from the real LoadConfig slot and
transparent thunk, not a name/RVA allowlist. Corpus bisects at `console_cfg`
**0x9c88** and `console_tls` **0x8874** exposed that missing input. The typed
dispatch slot is rebound while an unrelated decoy remains unchanged. Retained
host metadata is accepted only as an independently identical active original
graph when no replacement is generated; generated metadata checks stay strict.
These are semantic/ownership repairs, not pressure-masking bandaids.

| Issue / scope | H2 implementation and evidence | Remaining ownership |
|---|---|---|
| #15 frame/pressure recovery | Historical concrete-frame/home cutover; finite select repair #37 and bounded analysis/copy repairs #39–41 below | Original-population H2 gate remains open; no umbrella closure |
| #6 serial scheduling / zero-spill policy | Bounded scratch/memory homes retained; bounded DAG/CFG/phi work and one global pin map repaired | No return to zero-spill; no umbrella closure |
| #5 applicability | Requested existing MBA intensity retained in genuine transforming native/SDK cases below | Stronger/nonlinear MBA remains separate; raw normalized select ledger has no eligible MBA |
| #9 volatile-pinned live-across-call | After-definition capture/home delivery retained; supported-producer #38 disproof and actual-write saves #42 below | Arbitrary custom ABI and unsupported effects are not covered |
| #10 recursion/caller-frame access | Historical 486 caller-frame and 3 recursion recoveries; recursion 64/96 exercised; finite frame provenance repaired | Truly dynamic/unproved frame forms remain explicit; no umbrella closure |
| #13 signature precision | Existing metadata/CRT/import-thunk/inference path retained; exact authored contracts remain precise; unknown host calls consume all four GPR and XMM argument possibilities and retain RAX/XMM0 returns | No invented narrow signature or guessed unknown stack-argument count; broader signature work is not declared closed |
| #16 dead dependencies | Successor-aware per-bit analysis admits native flag writers only when their outputs are proved dead; partial writes, native reads, calls and memory effects retain their dependencies | Unmodeled native flag effects and variable-count carry semantics remain H5 work |
| #23 preservation | Historical 23/23 receipt above; current available 4/4 and stable 3,532-identity cohort below, without re-blessing originals/goldens | Original 23-member gate remains open; handler/personality and INT29 paths remain H5/H6; no umbrella closure |
| #8 preservation | Native physical operand pins/effects survive memory-backed lowering; native bit-string widths/offsets preserved | FS/GS and unknown native classes remain H5 limits |
| #17 bounded prerequisite | Existing one-plan reference/link ownership extended for frame/probe/helper and validated typed metadata consumers | Not whole-image compaction or every reference consumer; H4 retains global compaction |
| #20 bounded prerequisite | Actual-write saves and registered native-PC oracle below; ordinary supported call-contract concern scoped-disproved | **5 historical EhNoBucketCreation** and handler/scope/personality remain H6; arbitrary ABI is not proved |
| #30 bounded prerequisite | Validated BaseReloc storage classification retains the real relocation records and existing field rebasing/rebuild; code-shaped scalar headers no longer pin movers | HIGHLOW/opaque-reference limits stay conservative; global layout work remains H4, not issue-wide closure |
| #32 preserved prerequisites | The intact combined Rust callback executes identity/full MBA through the shared backend and linker | Compiled Rust startup, ordinary imports, std/runtime/TLS and lifecycle remain H3 |

The implementation-era snapshot retained **5 FrameDynamic** and **5
EhNoBucketCreation** rejections. Other unchanged semantic/reference reasons are
not declared repaired merely because the suite passes. FS/GS, variable-count
carry semantics, broader ISA/native classes and EH remain later work. H3 Rust
std/import/startup/lifecycle and H4 global compaction are not implemented here.
The intentional H1 generated loader remains; this is not a claim to have compiled
that loader or completed H3. **No remote issue is claimed closed.** The narrow
read-only-pin-save and duplicate-pin-map findings below are disposed within H2;
this does not pull all #36 output optimization or stronger MBA into H2.

### Post-acceptance review — 2026-10-22

The **historical review** withdrew acceptance at
`278f5ef81dd096e8325c06bd02ba7c88b84b0646` / publication `d1c70e1`, not the
historical counts or successful executions above. At that time #37 was a native
wrong-result reproduction; #38–43 were source findings, not measured native
crashes or wallclock slowdowns. The table is the **current authoritative
seven-finding disposition**, backed by the current repair section. Its scope
does not expand H2 into all #36, H3–H7 or language-handler reconstruction.

| Issue | Current evidence / status | Implemented result | Regression / oracle | Evidence limit |
|---|---|---|---|---|
| [#37](https://github.com/mkxto/kamy/issues/37) — finite select provenance | **Fixed**, `d87d989`; original wrong-result witness now passes both conditions | Finite Select/Phi/Copy provenance and final logical-coordinate mapping; delayed constants and separated final zones included | [Core frame regressions](../crates/kamy-core/src/frame.rs): `delayed_select_condition_is_independent_of_block_order`, `split_select_accesses_expand_only_actual_offset_alternatives`; [full-link native regressions](../crates/kamy-link/tests/memory_frames.rs): `exact_six_argument_select_ledger_witness_lowers_in_both_profiles`, finite phi/select/index/flags/call compositions; [actual values](../target/h2-repair/final-dll-values.log) | Exact normalized ledger has **0 eligible MBA**; adjacent and SDK witnesses genuinely transform at requested intensity **1.0**; truly unproved choices still reject specifically |
| [#38](https://github.com/mkxto/kamy/issues/38) — accepted call-contract unwind | **Scoped disproof**, `19bffa6`, for current supported ordinary Rust 1.95 / LLVM 22.1.2 CCC/FastCC producer | Actual compiled module, parsed definitions, resolved real CALL targets and reachable integer/Float64/mixed/aggregate/**24-byte SRet** contracts preserve Win64 nonvolatiles | [Ignored genuine-producer regression](../tests/sdk-rebuild/src/main.rs): `real_rust_llvm_call_contracts_preserve_win64_nonvolatiles`, explicitly rerun **PASS** after committed source; [final producer receipt](../target/h2-repair/real-producer-contract-final.log), SDK native-PC oracle | Not fabricated RBX/XMM6 metadata; not arbitrary LLVM/custom ABI or preservation-override attribute proof |
| [#39](https://github.com/mkxto/kamy/issues/39) — scalar-DAG work | **Fixed**, `b6f94b2` | Immutable-analysis cache memoizes success, failure and cycles; changed transform facts get fresh analysis | [Bounds regressions](../crates/kamy-core/src/frame/bounds/tests.rs): `scalar_shared_success_and_failure_dags_evaluate_once`, cycle/width/overflow/resource/fact-refresh cases; native indexed-frame consumers | Evaluated nodes **20,003/20,003 success**, **20,001/20,001 failure**; **40,002/40,000 edges**; no wallclock guarantee |
| [#40](https://github.com/mkxto/kamy/issues/40) — dominator storage | **Fixed**, `c0bfb28` | Candidate-free skip; petgraph immediate dominators plus Euler intervals, **linear storage**, **O(V²) worst-case time** | [Bounds regressions](../crates/kamy-core/src/frame/bounds/tests.rs): candidate-free 20,000-block CFG, loop scaling and **625** small-graph oracle choices; [allocation before](../target/h2-repair/frame-before.csv) / [after](../target/h2-repair/frame-after.csv) | No linear-time claim, threshold rejection or discarded CFG blocks; irreducible unproved frame bounds remain `FrameDynamic` |
| [#41](https://github.com/mkxto/kamy/issues/41) — phi-copy planning | **Fixed**, `32aaeb4` | Dependency/ready worklist and existing single cycle slot preserve simultaneous transfers | [Parallel-copy tests](../crates/kamy-codegen/src/isel/memory.rs), [native mixed-home phi-cycle consumer](../crates/kamy-link/tests/memory_frames.rs); [work receipt](../target/h2-repair/phi-planning-work.log): **16,384** chain/wide transfers use **98,303 / 81,920** work units | Constants, frame addresses, self copies, multiple cycles, GPR/XMM/flags covered; no incidental-register or elapsed-time oracle |
| [#42](https://github.com/mkxto/kamy/issues/42) — read-only pin saves | **Fixed**, `3a68d4c`; actual-write frame/save model and registered native unwind evidence | Read-only entry capture needs no dedicated save; native boundary reloads, partial/output/call writes still require real saves | [Codegen native regression](../crates/kamy-codegen/tests/memory_frames.rs): `nonvolatile_read_only_and_real_writes_preserve_results_and_caller_state`; [receipt](../target/h2-repair/nonvolatile-after.log); [full-width native oracle](../tests/sdk-rebuild/src/native_probe.rs) | Full 128-bit XMM preservation; read-only/native-read/partial-write registered PC checks **21/40/32**, body **14/28/19**, epilogue **3/7/7**; not arbitrary handler unwind |
| [#43](https://github.com/mkxto/kamy/issues/43) — duplicate global pin map | **Fixed**, `57eb3b1` | One authoritative global pins map; private instruction-local state bounded to four values, consumers migrated without compatibility aliases | [Memory selector](../crates/kamy-codegen/src/isel/memory.rs), native identity/MBA/call/phi consumers; [isolated pin receipt](../target/h2-repair/pin43-only.csv) and metric table below | Object and allocator reductions are measured separately; whole-campaign allocator reduction also includes other repairs, not all attributable to #43 |


#### Historical finite CMOV/select counterexample — before #37 repair

The native witness uses the Win64 six-`u64` call contract: arg1 is the condition,
args2–4 are zero, arg5 is `0x1122334455667788` and arg6 is
`0x8877665544332211`. Protect only this function through the existing
`crates/kamy-link/tests/memory_frames.rs` fixture/encode/protect/native mapper,
using the exact six-argument signature and identity (`mba=false`):

```asm
sub rsp, 24
lea rax, [rsp+8]
lea rdx, [rsp+16]
test rcx, rcx
cmovne rax, rdx
add rax, 56
mov rax, [rax]
add rsp, 24
ret
```

At entry RSP `E`, the selected pointers are `E-16` and `E-8`; adding 56
reaches `E+40` / `E+48`, the fifth/sixth argument. The actual
producer → SSA → link → machine path ran through `kamy_run::run_traced`:

```text
ssa_lowered=true rejected=[]
condition=0 original=0x1122334455667788 identity=0x00000051b28ff0c0 match=false
condition=1 original=0x8877665544332211 identity=0x00000051b28ff810 match=false
exit=Some(0) timed_out=false fault=None
```

The wrong pointer-like values are run-specific. The harness prints comparisons
and exits normally: exit 0 is NOT a correctness oracle. Local supporting source
`C:/dev/kamy-handoff2-select-review.rs` and
`target/sdk-rebuild-handoff2/select-review-runtime.txt` are supplemental, not
portable regression prerequisites. This finite supported witness MUST lower
correctly in identity and requested supported MBA, not be rejected wholesale,
special-cased or run at lower intensity. Truly unprovable selections may reject
specifically and atomically.

#### Historical NOW pre-repair acceptance net — not an H2 repair

This historical work made bad verdicts observable through existing tools; it did
not change frame proof, lifting, code generation or unwind. At this snapshot all
seven findings remained unfixed. It re-caught #37 **through `kamy corpus verify`**,
not only a standalone harness or exit-code check. The intentionally failing
external case was not a deliberately red workspace test. These receipts do not
imply then-unmeasured #39–41 work or the later #38 producer disproof; current
dispositions and passing native evidence are recorded separately below.

Corpus source identity is distinct from the historical lock. The available
checkout is `C:/dev/kamy-corpus`, with published source HEAD
`df9431c03da55fe0432608740ba5d29c78951860` (four historical members).
`corpus.lock` instead names `d9bc70d9970d3e1988203acd3415b103bcb62197`;
fetching that revision failed with `not our ref`. Do not label this checkout a
reproduction of the historical 23-member locked campaign, change those historical
counts, or claim the lock was retrieved. Record local witness additions and the
actual source/build/input/output identities separately. Immediately after clone,
`members/dll_strutil/orig/dll_strutil.dll` appeared modified; the integration
owner subsequently confirmed Windows Defender quarantine, not a source edit.
`Get-MpThreatDetection` reported `ActionSuccess=true`, `ThreatID2147902117`
and that exact file resource; its original directory is now empty. The user
directed **skip it** because Defender cannot be disabled. No security setting
was changed and no original restored. Report `dll_strutil` as unavailable /
skipped, never PASS; a subset run cannot establish an all-green full published
baseline. Do not rebuild, overwrite or re-bless this original. All existing
goldens remain untouched. Available members may be exercised individually,
with their exact population and this exclusion disclosed.

The new `dll_frame_select` original implements the six-`u64` witness above,
exported as `frame_select`, with `lower_exports: [frame_select]`. Its two loader
calls exercise conditions 0 and 1 independently and MUST return arg5 and arg6
respectively before blessing. No `expected_exit` override is needed: the loader
requires exit 0 and both real return values. Keep the original and its golden
distinct from protected output. Use `kamy corpus bless --corpus <checkout>
--member dll_frame_select` to bless only that member; never re-bless existing
members or bless the known-bad protected result. A missing/empty selection fails.

Before blessing, the integration owner executed the original in a child through
`kamy_run::run_traced` and recorded `target/pre-repair-now/original-native.txt`:

| Condition | Observed original result | Independent expected result | Match |
|---|---|---|---|
| 0 | `0x1122334455667788` | arg5: `0x1122334455667788` | true |
| 1 | `0x8877665544332211` | arg6: `0x8877665544332211` | true |

The reported original run exited `Some(0)`, with `timed_out=false` and
`fault=None`.

This independently establishes both original return oracles, not a protected
verdict or workspace-gate result. The user subsequently entered a Defender
preference themselves; the integration owner's read-only query showed no
matching visible exclusion, which does not prove the user's command failed.
No agent changed security settings or restored the old DLL; `dll_strutil`
remains skipped.


The member's opt-in `lower_exports` selects named **host exports** for identity
lowering, and every named target MUST actually lower. A missing, rejected or
unlowered target fails the campaign; matching a name or receiving any aggregate
coverage is not enough. Empty `lower_exports` preserves all-functions identity
selection for existing members. The loader `exports` entries still carry the
exact six argument tokens, including two calls to the same selected export.

Run health is separate from equality: timeout or missing termination always
fails. An actual traced fault fails unless the member explicitly declares its
matching `expected_exit`. Such a fault may have no normal exit event; the
validated traced terminal code populates the existing golden exit field, not
a claim of normal exit. Normal nonzero exit remains valid without an exact
expectation, and a declared `expected_exit` must match. Do not classify faults
by guessed PE/NTSTATUS-shaped exit values. Generic differential verification
has no expected-fault exception; the DLL loader protocol always requires exit 0
and real result output, never equal empty failures.

Use `corpus doctor --member dll_frame_select` to validate that original against
its golden, then `corpus verify --member dll_frame_select --keep` to retain the
exact protected binary plus the
existing versioned debug-map CSV and link-report JSON. Inspect selected/eligible/
lowered per-function outcomes and exact source-to-final mappings. For a runnable
EXE replay, `bisect --stdin-file ... --timeout ... --expect-stdout ... --keep`
must preserve the same stdin, timeout and output oracle in every probe and the
final replay, retaining the actual final failing artifact rather than rebuilding
a different one. DLL loader calls remain corpus oracles; do not pretend bare-DLL
EXE bisection replays their protocol. Capture actual commands, hashes, IR and
native output evidence. Observations below are initial integration evidence,
not final gates or H2 acceptance. No commit or push is part of this work.

##### Initial pre-repair integration observations — 2026-10-23

After the independent native original checks above, selected blessing succeeded
with **1 member / 1 blessed / 0 failed**, without re-blessing existing members.
The integration owner then observed the required corpus detection:

```sh
kamy corpus verify --corpus C:/dev/kamy-corpus --member dll_frame_select --keep --write-baseline target/pre-repair-now/frame-select-initial.yml
```

The command exited **1**, with both return-value comparisons failing:

| Condition | Golden return | Observed protected return |
|---|---:|---:|
| 0 | 1234605616436508552 | 593721617664 |
| 1 | 9833440827789222417 | 0 |

This re-catches confirmed #37 through **`kamy corpus verify`**, not just a local
harness or process exit. Initial coverage was **1 selected / 2 eligible /
1 SSA-lowered / 0 transformed / 0 relocated / 1 rejected**; the sole rejection
was deselected `DllMain`. Required host export `frame_select` lowered from RVA
`0x2000` to `0x4000`, with **136-byte frame / 24-byte original frame / 9 homes**.
The exact kept binary is
`C:/dev/kamy-corpus/protected/kamy-protected-dll_frame_select-9564.dll`, with
`.debug-map.csv` and `.link-report.json` appended to its full path. Hashes
reported for this initial execution are:

| Artifact | SHA-256 |
|---|---|
| CLI | `e8b0a1a91e681096af9c046c363766c93303b618d6b7b9dee3997f1494819d95` |
| Original DLL | `1e33abcfb8cbae9cd5b195985616154dc46c4a680e1ed6d0925d3c82805e4a60` |
| Protected DLL | `8d641395f54772160c9d9f834408dbbcf0ab7e4d3635348332e51ade02e440bd` |

The integration owner retained the immutable initial CLI snapshot under
`target/pre-repair-now/tools-initial` and used it to dump the original DLL at
RVA `0x2000` through `lift`, `ssa`, `optimize` and `regalloc`. All four commands
exited **0**; evidence files are `target/pre-repair-now/initial-<stage>.txt`.
The reported allocation dump contains `Select [v56, v49, v47]` followed by an
addition of 56 and a load. Only the `FrameAddress` alternatives appear in the
entry-offset map; the select has no derived offset. This is observed pre-repair
IR evidence, not proof that frame provenance was repaired.

The four historical `expected.yml` records were compared with source HEAD using
`git diff --exit-code` and were unchanged. Initial runner-health CLI probes also
observed an empty corpus exiting **1** (`contains no members`), equal UD2-fault
children rejected by generic differential verification with exit **1** and
execution mismatch (fault code **3221225501**), and a healthy identical
`console_fibmix` differential comparison passing. These scoped checks do not
establish a full published-corpus baseline or final gates.


The first integration workspace gates passed **451 tests / 47 suites**. Later
integration corrections to required-rejection coverage and replay/artifact
tests were still underway at this observation; these are not final union gates.
No protected correctness success, doctor success, historical full-corpus PASS,
H2 repair or acceptance is implied. `dll_strutil` remains unavailable/skipped.

##### Corrected integration observations — before runner-lifecycle repair

After integration corrections, the owner observed format check, denied-warning
clippy, build and workspace tests all succeeding: **454 tests / 47 suites**.
These supersede the initial 451-test observation only for this pre-lifecycle
snapshot; they are not final gates after the subsequent runner repair.
Selected `corpus doctor` runs for `console_fibmix`, `gui_msgbox`, `kernel32` and
`dll_frame_select` each exited **0**. The corresponding available-population
corpus runs used `--keep` and wrote
`target/pre-repair-now/final-<member>.yml`, with logs
`target/pre-repair-now/final-verify-<member>.txt`:

| Available member | Observed command exit / protected verdict | SSA lowered / rejected |
|---|---|---|
| `console_fibmix` | 0 / PASS | 36 / 313 |
| `gui_msgbox` | 0 / PASS | 139 / 383 |
| `kernel32` | 0 / PASS | 760 / 949 |
| `dll_frame_select` | 1 / FAIL — required known wrong-return witness | 1 selected / 1 lowered / 0 transformed |

Selected doctor logs are `target/pre-repair-now/final-doctor-<member>.txt`;
all four selected originals passed with command exit **0**. The new witness's
independently blessed golden requires condition 0 to return
**1234605616436508552**, but the protected observation was **38381022928**;
condition 1 requires **9833440827789222417**, but observed **0**. The exact
retained DLL is
`C:/dev/kamy-corpus/protected/kamy-protected-dll_frame_select-22076.dll`,
with its retained sidecars. Required-lowering failures also preserve actual
coverage and diagnostics; a failed requirement is not reported as zero coverage.

`dll_strutil` remains quarantined and skipped, not PASS. These are four
individually selected available members, not the historical 23-member campaign
or a healthy full published baseline. Final health probes again rejected the
empty corpus and equal actual UD2-fault children with command exit **1**; an
identical healthy `console_fibmix` original comparison passed despite its normal
nonzero golden exit **7**. The integration owner also checked that production
`core`, `lift`, `codegen`, `seh` and `link` had no diff.

The real stdin/output-aware EXE `bisect` smoke did **not** complete. It used a
temporary EXE form of the same witness with `--expect-exit 0`,
`--expect-stdout <expected-output>`, `--stdin-file <input>`, `--timeout 10` and
`--keep`; removing `probe-1.exe` after the traced baseline run failed with access
denied. Runner/debugger handle and evidence ownership require lifecycle repair,
not ignored cleanup errors or blind retries. No successful actual CLI replay was
established by this snapshot. Unit-test/gate success did not establish completed
CLI replay or the NOW deliverable; H2 was reopened and no #37–43 repair was then
claimed.

The subsequent runner/triage lifecycle implementation now acknowledges debug
exit events and waits for process termination; preserves the first second-chance
fault while continuing it unhandled; and checks timeout job termination, drains
debug events and reaps processes under a separate 10-second cleanup bound.
Its regression uses copied test executables and immediately removes each image
after context, fault and timeout runs. No H2 backend change is included.

##### Historical final NOW acceptance net — lifecycle repaired, H2 still reopened

After removal of incidental elapsed-time assertions, the integration owner ran
format check, denied-warning clippy, workspace all-target build and tests:
**all PASS, 455 tests / 47 suites**. The initial 451 and intermediate 454 totals
above are historical integration snapshots. That snapshot's exercised root CLI was
`target/debug/kamy.exe` (snapshot `target/pre-repair-now/tools-current`), SHA-256
`aa724a6156a8416a326f9acb9bcdfa0ff20b4d2fcad8e6693e8a1ca55772f52c`;
loader SHA-256
`ac1d95e966582b76ad824a64e72d11f7bf0e924ca6c6aa5a0a6e5ba30404c334`.
The final identities/results are in `target/pre-repair-now/receipt.json`.
The earlier `tools-final` / `718e402d…` run is a historical successful smoke.

Actual CLI bisect now succeeded with command exit **0**, **43 candidates**,
**13 steps**, culprit **0x19000**. Full command/output is retained in
`target/pre-repair-now/current-bisect.txt`:

```powershell
target/debug/kamy.exe bisect target/pre-repair-now/bisect_probe.exe --expect-exit 0 --expect-stdout target/pre-repair-now/bisect-expected.txt --stdin-file target/pre-repair-now/bisect-stdin.txt --timeout 10 --keep
```

The exact replay is
`C:/Users/a930276/AppData/Local/Temp/kamy-triage-19684-0/replay.exe`, SHA-256
`2df432c273ec5666bbd328ab2b00d54e8f8b4a8331e9c44bbbaa90e6ae52aee7`.
An evidence copy is `target/pre-repair-now/bisect-replay.exe`; input EXE SHA-256
is `5044514c51696dfcabebfa0ea06c4a4b5aa8c826c204eed1ac5ee6a601989fcf`.
The earlier successful smoke's `accepted-bisect-regalloc.txt` confirms the same `Select` / add 56 / load
witness, generated frame **136 bytes**, original reservation **24 bytes**.
The prior access-denied cleanup failure is resolved by lifecycle ownership, not
suppression or a blind retry. Probe sources were throwaway; immutable tools,
input/output, maps and logs are retained.

Post-lifecycle selected doctors for all four available members again **PASS**;
the three available historical members again **PASS** protected verification.
The new `dll_frame_select` again correctly **FAILS** the acceptance oracle:
condition 0 expected **1234605616436508552**, observed **500008219856**;
condition 1 expected **9833440827789222417**, observed **0**. The current exact
artifact is `C:/dev/kamy-corpus/protected/kamy-protected-dll_frame_select-21892.dll`
plus sidecars, SHA-256
`8d641395f54772160c9d9f834408dbbcf0ab7e4d3635348332e51ade02e440bd`.
Current logs and baselines use `target/pre-repair-now/current-` prefixes.
Earlier `accepted-` logs record the historical `-17760.dll` run with condition
0 observing **320099839520**. Wrong values differ despite identical DLL bytes;
none is an oracle. Preserve the independently correct original/golden. All
four historical goldens remain unchanged against published HEAD; production
`core`, `lift`, `codegen`, `seh` and `link` remain unchanged against source HEAD.

Temporary real health controls observed: declared UD2 fault
`expected_exit: -1073741795` blessed and doctored with exit **0**; the same
undeclared fault failed blessing with exit **1** and no golden; generic equal-
fault verification and empty-corpus verification each exited **1**. Healthy
console comparison passed with normal exit **7**. These controls are not corpus
baseline members. Quarantined `dll_strutil` remains user-skipped, not PASS;
there is no full historical four- or 23-member baseline claim.

The **historical NOW evidence net was complete**, including actual same-oracle
EXE replay, the required failing corpus witness and run-health checks. It did not
constitute protected correctness acceptance: H2 remained reopened and all seven
#37–43 findings were unfixed **at that pre-repair snapshot**.



#### Mandatory reacceptance evidence ledger

The [numbered H2 acceptance matrix](handoffs/02-memory-backed-lowering.md#required-acceptance-matrix)
retains its semantic, runtime and original-population gates. The user explicitly
authorized this **Kamy-only headless campaign, without IDA/x64dbg**, replacing
literal debugger-tool wording, not the required machine/ABI/manual proof. No
IDA/x64dbg gate was executed or is claimed green. Truly debugger-dependent
findings would stay blocked; none was found in the exercised evidence.

The current section records source/build/input/output identities, commands,
symbol/RVA and native-PC/address annotations, exact output-value oracles,
accepted producer/call-result contracts and independent Windows
`RtlLookupFunctionEntry` / `RtlVirtualUnwind` checks under forced ASLR. Manual
triage/bisect, lift/SSA/optimize/regalloc/native dumps, identity/requested-MBA
protection and explain-reject evidence remain required as applicable. Actual
DAG/CFG/phi work/allocation is evidence, not flaky wallclock assertions. Portable
regressions carry platform gates; local receipts are supplemental, not portable
fixture prerequisites. Tests alone, screenshots or decompiler prettiness are not
correctness proof. The original locked-corpus gate remains **incomplete**.

The following **historical, pre-repair** `demo-frame-identity.dll` observation used `frame.yml` plus
`--ssa-identity`: **8 selected / 8 lowered / 0 transformed**, actual intensity
**0.0**. Its headless SDK probe printed
`frame_runtime=PASS depth=64 original_object=4096 large_object=24576 aslr=1`,
with `exit=Some(0)`, no timeout and no fault. `frame_mix6` moved from source
RVA `0x10c0` to `0x69a0` (VA `0x1800069a0`): **39 → 443 bytes**, frame
**224 bytes**, **24 homes**. IDA initially split the function at state ranges
of **7 / 435 / 1 bytes**. The integration owner coalesced IDA function
definitions to the link report's 443-byte extent, applied the real six-`u64`
Win64 source ABI and reanalyzed without changing binary bytes. Hex-Rays then
returned `8*e + ((a+3*b) ^ (d+5*c)) - e - 11*f`.

This is identity-only output-quality context for #36, not proof of MBA behavior,
the select fix or custom-clobber unwind. The demo passed while the separate
selected-pointer witness failed both conditions. IDA version evidence was not
collected for this observation; it does not satisfy the expanded gate. Supporting
`.dll.i64`, `.c` and `.logical.asm` files are ignored target artifacts, not portable
prerequisites. IDA function fragmentation is not an unwind defect: equal states
already coalesce, while distinct ranges follow the current zero-prologue
state-snapshot model. No requirement to eliminate all memory-home traffic is
added. Historical identity/MBA runtime and native-unwind successes above remain
scoped to their recorded fixtures, not universal acceptance.


### Current H2 repair evidence — 2026-10-23

**All seven findings are disposed as recorded in the ledger above; formal H2
remains incomplete solely for the original-population corpus gate. H3 waits.**
This is the user-authorized Kamy-only campaign: **no IDA/x64dbg was run**. Exact
machine bytes/PCs, ABI/address math, native outputs and independent Windows unwind
proof were exercised; debugger-specific proof was not silently declared green.
D16/D22/D24/D40, the source schemas, originals/goldens and security policy are unchanged.

**Fresh integration gates:** format check, `clippy --all-targets -- -D warnings`,
workspace all-target build and workspace tests all **PASS: 503 tests / 47 suites,
1 ignored**; [gate receipt](../target/h2-repair/refined-gates.json) and
[`refined-{fmt-check,clippy,build,tests}.log`](../target/h2-repair).
The ignored genuine-producer test was separately invoked with explicit
`SDK_ABI_{KAMY,CARGO,RUSTC,LINKER,OUT}` and `KAMY_LLVM_TOOLS_DIR`, and **PASS**:
`cargo test -p kamy-sdk-rebuild-acceptance --bin sdk-rebuild tests::real_rust_llvm_call_contracts_preserve_win64_nonvolatiles -- --ignored --exact --nocapture`.
Its [final committed-source rerun receipt](../target/h2-repair/real-producer-contract-final.log) records actual
Rust **1.95.0** (`59807616e1fa2540724bfbac14d7976d7e4a3860`), LLVM
**22.1.2-rust-1.95.0-stable**, target **x86_64-pc-windows-msvc**, parsed compiler
metadata and resolved reachable calls, not arbitrary ABI labels. The genuine
24-byte SRet helper is in [callback.rs](../tests/sdk-rebuild/plugins/callback.rs);
the [producer test](../tests/sdk-rebuild/src/main.rs) checks integer, scalar
Float64/XMM0, mixed RAX/XMM0, aggregate and hidden-return contracts. The scoped
#38 conclusion excludes preservation-override attributes and arbitrary custom ABI.

**Native #37 result and profile:** [final values](../target/h2-repair/final-dll-values.log)
show original, identity and requested ordered probability-100 sub/add outputs all
equal **1234605616436508552** (condition 0) / **9833440827789222417** (condition 1),
through the traced real loader, exit **0**, no fault/timeout. The exact normalized
ledger has **0 eligible arithmetic / 0 actually transformed**; calling it an MBA
transformation would be false. Adjacent split-zone/scalar native cases and the
SDK **8/8** MBA exports genuinely transform at requested intensity **1.0**.
Portable [link fixtures](../crates/kamy-link/tests/memory_frames.rs) cover exact
six-argument select, finite phi/copy/index, nested/mixed-zone consumers, flags and
successive calls; [core fixtures](../crates/kamy-core/src/frame.rs) also cover bounded
shared DAGs. Two additional before/after edges are retained: delayed dominating
constant in a later-numbered block **`FrameDynamic` → proved E+40**
([before](../target/h2-repair/select-order-before.log) / [after](../target/h2-repair/select-order-after.log));
finite **E−32/E−16 + 24 → safe E−8/E+8** alternatives
**`FrameConflict` → accepted**, without inventing a crossing interval
([before](../target/h2-repair/select-split-before.log) / [after](../target/h2-repair/select-split-after.log)).

**Representative machine annotations:** source body **RVA 0x2000..0x2021 (33 B)**
becomes **0x4000..0x409c (156 B)**; original reservation **N=24**, generated **S=136**,
entry RSP **E**, final body RSP **B=E−136**. At **0x4048** CMOV selects
**B+8/B+16**; **0x4056** adds **S−N=112**, **0x405a** adds **56**, reaching
**E+40/E+48**. Load **0x4068**, stack restore **0x4094**, return **0x409b** are
in the [exact native dump](../target/h2-repair/final-native-fixed-inspection.log).
Real ABI scalar call **source 0x104b → 0x11c0**, final **0xa04c8 → 0xa0b70**,
captures XMM0 at **0xa04cd `[rsp+0x150]`**; mixed call **0xa0579** captures
RAX/XMM0 at **0xa057e/0xa0586**, before later calls
([caller dump](../target/h2-repair/final-abi-caller-native.log)). These are RVAs,
not claimed runtime ASLR addresses.

**Bounded work/allocation:** #39 caches success/failure/cycles; #41 chain/wide work is bounded as measured above. #40 skips candidate-free dominators; needed storage is linear, worst-case time **O(V²)**.
Measured comparisons below use bytes unless marked; old CFG runs safely stop at **256/512 blocks**.

| Metric | Before | After | Scope |
|---|---:|---:|---|
| #40 requested allocation | 857,582,864 | 27,792 | Acyclic 512; [before](../target/h2-repair/frame-before.csv) / [after](../target/h2-repair/frame-after.csv) |
| #40 peak live delta | 2,770,024 | 25,140 | Same acyclic 512; reducible bounds / irreducible `FrameDynamic` preserved |
| #42 frame size | 96 | 64 | Read-only entry pins |
| #42 dedicated save count | 2 | 0 | Read-only entry pins; count, not bytes |
| #42 save storage | 24 | 0 | Read-only entry pins |
| #42 code size | 115 | 95 | Read-only entry pins; [native receipt](../target/h2-repair/nonvolatile-after.log) |
| #43 `RegAllocation` size | 680 | 624 | Duplicate global map removed |
| #43 allocator bytes | 6,547,182 | 6,399,346 | 8,192 pins; [before](../target/h2-repair/pin-before.csv) / [isolated #43](../target/h2-repair/pin43-only.csv) |
| Campaign allocator bytes | 6,547,182 | 6,350,178 | Same pins; [campaign](../target/h2-repair/pin-after.csv), includes other repairs, not all #43 |

New-only **2,048/8,192** CFG cases imply no old large-input run; no timing claims/assertions.
#42 real native-read/partial-write cases still save RBX/XMM6: **128 B** frames,
**187/150 B** code. Registered native checks preserve full **128-bit XMM** state, not only Float64 lanes.

**Fresh SDK full:** the documented `sdk-rebuild all --scope full` command was run
with explicit compiler/linker/library paths into `target/h2-repair/sdk-final`:
**exit 0 / full PASS**, rebuilding **11 normal artifacts + 1 dynamic negative**
([full command/log](../target/h2-repair/sdk-final-all-full.log),
[summary](../target/h2-repair/sdk-final-summary.json)). Intact combined callback
identity/MBA executes **trace 12 / bounds 24**, frames **176/320 B**, without split,
skip or intensity reduction. Standalone identity/MBA each lower **8 exports**,
transforming **0/8** respectively, and execute depth **64**, original object
**4,096 B**, actual guard-page object **24,576 B**, forced ASLR. Independent `RtlLookupFunctionEntry` /
`RtlVirtualUnwind` probes cover **1,155/1,920 PCs**, **87/87 epilogue PCs**,
max frames **25,208/25,640 B**, saved **3 GPR / 1 XMM**. The ordinary dynamic
negative fails specifically `FrameDynamic`, with no output. These are real SDK
and registered native oracle results, not execution of every corpus body or EH parity.

**Available corpus:** measured source revision **`0664dda`**, **4/4 PASS** (now README-only HEAD `fdede7e`; binaries/goldens unchanged): three historical members
plus `dll_frame_select`; **935 historical lowered + 1 new witness**, identity
**0 transformed**. [Final stable-cohort receipt](../target/h2-repair/final-stable-cohorts.json)
compares exactly **3,532 historical identities**: **0 added / removed /
classification changes / rejection-reason migrations**; final per-member baselines
are `target/h2-repair/final-<member>.yml`. This is not a recovered 23-member run.
The lock's original revision **`d9bc70d9970d3e1988203acd3415b103bcb62197`** is absent
locally (`cat-file` exit 128; prior fetch `not our ref`); the original population or
published revision is required. Original `dll_strutil` stays **quarantined/user-skipped**,
never restored, rebuilt or re-blessed. No original, golden or security baseline changed.

**Manual tooling:** actual `dump` lift/SSA/optimize/regalloc and exact
`dump --stage native --size` inspected selected/indexed/phi/call consumers;
`explain-reject` reports host `LiftFailure`, mandatory dynamic injection reports
`FrameDynamic` with no output. Same-oracle stdin/stdout-aware EXE bisect now has
all-lowered success and exits **1 / nothing to bisect**, not a new failure
([receipt](../target/h2-repair/final-bisect-after.log)); historical culprit **0x19000**
remains the before-repair receipt. Official rust-analyzer **1.95** direct LSP
references/diagnostics worked; host-mounted transport timed out and one cross-package
`#[path]` **E0583** remains despite actual compiler/native PASS. Session-private mode
was left unsaved as requested. Local logs/probe binaries are evidence, not new
portable prerequisites; source fixtures linked above are authoritative.

**Final identities:** [final-identities.json](../target/h2-repair/final-identities.json)
records all **17** exercised tool/input/output identities, byte sizes and full versions,
including Kamy **0.0.0**, rust-analyzer **1.95.0** and LLD **22.1.7**. SHA-256:
CLI `d0591b66a70d0cc515b6df457e579cc4c65ee86cafd5af701ee706d06a70c2f6`;
loader `d658e3514720ad2da33135d43c8df9e4d69092312056066dd4096faac9a4988a`;
original select input `1e33abcfb8cbae9cd5b195985616154dc46c4a680e1ed6d0925d3c82805e4a60`;
identity and requested-profile outputs both `44a34ee2c424d07d215a9f05d87af8dda7c83f8605212a707c14eeb5ace61a50`
(identical bytes agree with **0 eligible MBA**, not a transformation claim).
SDK frame original / identity / MBA hashes are respectively `9109fb244d752fee873d339ffbbf7bffea89502fcb2965feb4461ea74db632b6`, `5bed2fc49132f7a591f1bc5c0b592599cf3c7d66c1460cbaf8d7c280625a02d3`, `a29f9550390800b98167d375dbdfc9ee4c33e2d003df72365c265548662e0df6`.

