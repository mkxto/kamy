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
| SSA construction (maximal phi insertion + renaming) | Done | `1cfc37b` |
| Optimizer (constprop, instcombine, DCE, prune-phis, convergence) | Done | `1cfc37b` |
| DCE live-out fix (`Use` ops before `Ret` for RAX + callee-saved) | Done | `88e9e8a` |
| Register allocator (linear-scan, zero-spill hard constraint) | Done | `1cfc37b` |
| Instruction selector (IR → x86, flag fusion, NativeInline re-emit) | Done | `1cfc37b` |
| RSP pinning (lifter tracks RSP chain, regalloc pins to physical RSP) | Done | `26216be` |
| Callee-saved interfaces (regalloc pool + isel push/pop) | Wired | Activation deferred to Phase 4 |
| Relocating linker (thunks, .kamy section, .pdata rebuild, scrub) | Done | `b29b83b` |
| SSA linker path (lift→ssa→opt→regalloc→isel→encode + fallback) | Done | `13196a1` |
| No-transform relocation round-trip (169 functions, verified) | ✅ Proven | `b29b83b` |
| No-transform SSA round-trip (169 functions through SSA, verified) | ✅ Proven | `88e9e8a` |
| MBA pass (add/sub/xor rules, D13 config shape) | Done | `1cfc37b` |
| MBA probability fix | Done | `fa6b941` |
| MBA visible output | **Blocked** | Regalloc needs callee-saved (Phase 4) |
| Win32metadata calling-convention DB | Deferred | Trait wired + Win64Default + WinmdLookup todo!() |

### Known lifter bugs (from external IR analysis)

1. **CALL clobbers all registers instead of only volatiles.** RSP and callee-saved
   (RBX, RBP, RSI, RDI, R12-R15) should survive calls. Root cause: `lift_call`
   clobbers everything with Undef. Fix: only clobber volatile regs per Win64 ABI.
2. **Return-address push is materialized.** `Store(rsp, const_return_addr)` before
   Call could be folded into the Call node. Optimization, not correctness.
3. **Over-approximated call args.** Win64Default passes 4 args for every call.
   Resolved by Win32metadata DB (D14) or PDB symbol lookup.

## Phase 3 — Obfuscation Passes

| Item | Status |
|------|--------|
| ObscureReferences | Not started |
| ObscureConstants | Not started |
| MutationEngine | Not started |
| LoopEncodeSemantics | Not started (underspecified — needs design) |
| Per-function config profiles + symbol matching | Not started |
| Jump table recovery & retargeting (D24) | Not started |

## Phase 4 — SEH & CET

| Item | Status |
|------|--------|
| Callee-saved activation (RSP alignment + push/pop) | Interfaces wired, activation blocked on UNWIND_INFO |
| UNWIND_INFO reconstruction (kamy-seh) | Not started |
| C_SCOPE_TABLE re-pointing | Not started |
| CET shadow stack reconciliation | Not started |
| MSVC SEH test suite (58+ tests, D11) | Not started |

## Phase 5 — Advanced Passes

Not started. CFF, opaque predicates, polynomial MBA, dead-code injection,
known-bits abstract domain, cost-gated expression simplifier.

## Phase 6 — Production

Not started. Coverage reporting, API server, CI integration, ELF, ARM64.

---

## Test corpus

| Test | Status |
|------|--------|
| Unit tests (40 across 7 crates) | ✅ All pass |
| Relocation round-trip (target.exe, 169 functions) | ✅ Verified (exit=7, ASLR-stable) |
| SSA identity round-trip (target.exe, 169 functions) | ✅ Verified (exit=7) |
| kernel32.dll analysis (2588 functions, 29717 blocks) | ✅ Verified (headers cross-checked) |
| aftermathlabs/bintests corpus (D25) | Not adopted |

## Rejection rates

| Binary | Moved | Rejected | Rate | Top rejection |
|--------|-------|----------|------|---------------|
| target.exe (Rust) | 169 | 217 | 43.8% | BadIndirectBranch (114) |
| kernel32.dll | 1214 | 1374 | 46.9% | BadIndirectBranch (922) |

Jump table recovery (D24) is the #1 coverage improvement.
