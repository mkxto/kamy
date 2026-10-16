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
6. **Phantom discovery seeds.** Unaligned "functions" (target.exe 0xa4dc,
   0xb0b4, …; kernel32 0x40c1, 0x4391, 0x5bcf) sharing identical blocks with real
   functions — call-like decoding seeds functions inside other functions' code.
   Inflates function + rejection counts. Possible contributor: missing noreturn
   tracking (BLARE2's documented failure mode). Fix before any coverage metric is
   trusted; see research.md §10.2.

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
| Jump table recovery & retargeting (D24) | Studied | Design settled by research.md §10: layer 0 IAT/static-ptr classification → phantom-seed fix → layer 2 use-def DAG + petgraph VF2. Re-emit/retarget is our own gap (BLARE2 doesn't document it) |
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
| target.exe (Rust) | 169 | 217 | 43.8% | BadIndirectBranch (114) |
| kernel32.dll | 1214 | 1374 | 46.9% | BadIndirectBranch (922) |

Measured decomposition (jump-table study, research.md §10): kernel32's 922
`BadIndirectBranch` = 843 export forwarders (`jmp [rel IAT]`, 6–7 bytes, not
protection targets) + 67 internal static-pointer jumps (resolvable) + 12 real
register-dispatch functions (11 switch tables recoverable, 4 `jmp reg` dynamic).
target.exe's 114 = 59 static-pointer + 51 RVA-table blocks (recoverable) +
38 dynamic vtable tail-calls (honest rejections) + phantom-seed inflation.
Layer 0 (classify `jmp [rel X]` via IAT-range test, BLARE2-confirmed) + phantom-seed
fix + layer 2 (use-def DAG + petgraph VF2) are the D24 implementation order.

Jump table recovery (D24) is the #1 coverage improvement.
