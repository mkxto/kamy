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
| Register allocator (linear-scan, zero-spill hard constraint) | Done | `1cfc37b` |
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
| Pressure-aware transform budgeting (D28) | Partial | Intensity knob on the MBA pass landed (`run_with_intensity`); the retry-at-lower-intensity ladder is not wired. |
| Actual-body .pdata/UNWIND_INFO reconstruction (D31/#20) | Done for supported plain functions | Per-state v2 ranges describe body stack allocation and GPR/XMM saves; handler/scoped or unprovable states stay resident |
| Differential self-test harness (kamy-verify) | ✅ Done | `kamy verify --original X --protected Y`: exit + stdout diff over N seeded runs. The Phase 2 shipping gate. |
| 8/16-bit register write semantics | ✅ Done | `write_gpr_sub64`: 8/16-bit GPR writes merge into the live register (`(old & ~mask) | zext`) rather than zero-extending; only 32-bit zero-extends (x86). Fixed a latent partial-register miscompile (`mov al,X` dropped the destination's upper bits). `b3b326a`. |
| Callee-side argument inference (own functions) | ✅ Done | Leaf-only read-before-write liveness over the Win64 argument registers narrows signatures for the target's unnamed functions (`kamy-analysis::infer_signature`); sound-by-construction — tail-forwarding/indirect exits force all args live-out, ambiguous/non-contiguous prefixes bail to the four-arg default. +25 SSA-lowered / −26 RegisterPressure over the partial-register-fix baseline; corpus 21/23. `214e2ee`. |

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
over-budget function fails injection rather than being omitted or relocated
verbatim. A combined bounds-check/counter probe exercised this strict
`RegisterPressure` failure. Injection remains off by default, requires an
original entry point, and rejects kernel images before discovery.

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
pressure rejection/reduced intensity remain current backend limitations until
handoff 2. Enforcing module CFG and the vendor's unobserved extras remain outside
this epic's gates.

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
