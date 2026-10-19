# Kamy — Grilling Session

Design interrogation before writing code. Every decision here is load-bearing; later ones depend on earlier ones. The tree is walked root-first.

---

## Cross-Cutting Constraints

| ID | Constraint | Implication |
|----|-----------|-------------|
| C1 | No copy-paste / vendoring of other projects' code | Use crates as Cargo dependencies, never extract source. Reference designs are fine; lifting code is not. |
| C2 | Any lib dependency must be (a) somewhat maintained and (b) clearly not worth reimplementing | Every dependency must pass a "why not build it?" justification. Unmaintained or thin wrappers are out. |

---

## Evidence Base: What CodeDefender Actually Does

Before making architectural decisions, we investigated CodeDefender's public repos to ground claims in evidence rather than assumptions.

### Sources examined
- [codedefender-io/windows](https://github.com/codedefender-io/windows) — obfuscated ntoskrnl.exe + bootmgfw.efi with VirtualBox snapshot
- [codedefender-io/plugins](https://github.com/codedefender-io/plugins) — BLARE2 plugin SDK (function injection into PE)
- [codedefender-io/metrics](https://github.com/codedefender-io/metrics) — benchmark configs + obfuscated binaries vs Themida/VMProtect
- [codedefender-io/sigbreaker](https://github.com/codedefender-io/sigbreaker) — SigBreaker-scrambled LLVM binaries, tested against llvm-lit
- [codedefender-io/tether](https://github.com/codedefender-io/tether) — instruction extraction for remote execution

### Key findings

**1. Every function goes through the SSA IR — there is no non-IR path.**

The YAML configs from the metrics repo are definitive. Every profile — including "light protection" — contains:

```yaml
compiler_settings:
  lifter_settings:
    lift_calls: true
    calling_convention: WindowsAbi
    max_stack_copy_size: 512
    split_on_calls_fallback: true
  optimization_settings:
    constant_propagation: true
    instruction_combine: true
    dead_code_elim: true
    prune_useless_block_params: true
  assembler_settings:
    shuffle_basic_blocks: true
```

`lifter_settings` is mandatory and always present. "MutationEngine" is a pass *within* the SSA pipeline, not a separate byte-patching engine. The difference between "light" and "heavy" protection is **which passes run and how many iterations**, not which engine is used.

**2. Own linker with thunk placement and space reclamation.**

From the windows repo README: *"our linker will reuse free space."* The linker places transformed code and can reclaim the space from original function bodies. The benchmark rejection reason `NoThunkSpace` confirms thunks (stubs) are placed at original function sites — if the original function is too small for a thunk, the function is rejected.

**3. Can do whole-program or selective.**

ntoskrnl.exe: 10 specific functions selected by name/RVA. bootmgfw.efi: *"all available functions... whole program obfuscation."* The engine is whole-program-capable; selectivity is a user configuration choice.

**4. BLARE2 can inject new code, not just transform.**

The plugins repo demonstrates linking new C/C++ functions into an existing PE post-compilation, with symbol resolution and init-table registration. This is a full linker, not a patcher.

**5. SigBreaker: 100% parity on LLVM test suites, PE AND ELF.**

46K+ clang tests, 3K lld tests — identical pass/fail before and after. Linux ELF support with jump-table handling. Built with CodeDefender 1.2.4. This is a mature, battle-tested single engine.

**6. CodeDefender's observed pass types:**
- `ObscureReferences` — hide cross-references
- `ObscureConstants` — hide constant values
- `MixedBooleanArithmetic` — MBA with configurable semantics {add, sub, and, xor, or, not, neg} × bitwidths {8, 16, 32, 64}, iterations, probability
- `MutationEngine` — instruction mutation with SSE extension support, same semantics/bitwidth config
- `LoopEncodeSemantics` — loop-body encoding, same config shape

**7. Module-level settings observed:**
- `ida_crasher` — anti-IDA measures
- `import_protection` — import obfuscation
- `obscure_entry_point` — entry point hiding
- `clear_unwind_info` — strip unwind data (anti-analysis, at cost of exceptions)
- `fake_pdb_string` — inject fake debug path
- `custom_section_name` — rename output section

---

## Decisions

### D1 — Engine Model

**Question:** Single SSA IR engine (CodeDefender model) vs two-tier (separate non-IR mutation path)?

**Options considered:**
1. ✅ **Single SSA IR engine, pass-selectable** — one pipeline: lift → IR → ordered passes → compile → link. Protection level = which passes run + iterations.
2. ❌ Two-tier (separate non-IR mutation path) — doubles correctness surface, no evidence CodeDefender does this.

**Decision:** Single engine.

**Reasoning:** The architecture doc's "Tier 1 = PERSES/Theodosius model" was imported from a different project lineage (mike1k/perses). CodeDefender's configs prove there's no separate non-lifted path. Every function goes through `lifter_settings` → `optimization_settings` → `assembler_settings`. "MutationEngine" is a pass on the SSA IR, not a separate engine.

Two engines = two implementations of: EFLAGS preservation, relocation tracking, jump-table recovery, SEH/.pdata rebuild, CET reconciliation, verification. That's eight hard correctness subsystems duplicated. One engine with configurable pass selection gives the same user-facing flexibility without the maintenance burden.

**Implications:**
- Kill "Tier 1" and "Tier 2" framing in architecture.md. Replace with "pass depth" (shallow = MBA/mutation only, deep = CFF/opaque predicates).
- The lifter is THE critical-path engineering effort — every function flows through it.
- "No transform" functions are still free: they're simply not selected by the profile.

---

### D2 — Linker Strategy

**Question:** How does the linker handle transformed functions?

**Options considered:**
1. ✅ **Thunk at original site + new section for transformed code** — original function body overwritten with a short stub redirecting to transformed code in a new `.kamy` section. PE structurally rebuilt.
2. ❌ Thunk + space reclamation — same as above but linker reuses freed space. CodeDefender does this ("our linker will reuse free space") but it's a v2 optimization.
3. ❌ Full image re-layout — no thunks, re-point everything. Requires perfect whole-program symbolization.

**Decision:** Thunk + new section. Space reclamation deferred.

**Reasoning:** The `NoThunkSpace` rejection in CodeDefender's benchmark output confirms thunks are the mechanism. If the original function is too small for a thunk, it's rejected — that's the evidence.

Thunk model bounds the symbolization problem: you only need to symbolize *inside* transformed functions + their direct outbound references. Inbound references to the function hit the thunk and redirect automatically. You don't need to find and re-point every caller.

Space reclamation ("our linker will reuse free space") is a size optimization that can be added later without architectural changes. It just means the linker has a free-list of reclaimed original-body regions.

**Implications:**
- Thunk format: `jmp rel32` (5 bytes) for near, `jmp [rip+0]; dq addr` (14 bytes) for far. Minimum original function size = 5 bytes.
- Functions smaller than thunk size → rejected (matches `NoThunkSpace`).
- Direct `call` instructions whose target is a transformed function CAN be re-pointed directly (avoiding the thunk indirection) when the caller is also being transformed. Optimization, not required for correctness.
- Original function body should be scrubbed (zeroed or filled with `int3`) after thunk placement to prevent analysts from reading the original code.

---

### D3 — CALL Handling in the Lifter

**Question:** How does the lifter handle CALL instructions?

**Options considered:**
1. ✅ **Lift calls (model in IR) + split-on-call fallback** — model CALL in the IR with explicit register/stack effects when calling convention is known. Split function at call site when convention is unknown.
2. ❌ Opaque CALLs (barrier + full clobber) — simpler but worse codegen (can't optimize across calls).
3. ❌ Split on every call — simplest but transforms are limited to intra-call regions.

**Decision:** Lift calls with fallback.

**Reasoning:** CodeDefender's config explicitly has `lift_calls: true` and `split_on_calls_fallback: true`. This is the most capable approach: when you know the calling convention, you can model exactly which registers are args (RCX, RDX, R8, R9, XMM0-3 for Win64), which are clobbered (RAX, RCX, RDX, R8-R11, XMM0-5), and which are preserved (RBX, RBP, RDI, RSI, R12-R15). This lets the register allocator work across call boundaries.

The fallback (`split_on_calls_fallback`) handles functions where a call target's convention is unknown: the function is split into regions at call boundaries, each lifted and compiled independently. This is still correct — just less optimizable.

**Implications:**
- Need a calling convention database. k0mkc uses Win32metadata for ~20K functions across 350 DLLs as perfect hash tables. We need something equivalent.
- Win32metadata source: [microsoft/win32metadata](https://github.com/microsoft/win32metadata). Need to extract function signatures → arg types/counts/noreturn annotations.
- PDB provides calling convention info for the target binary's own functions.
- `max_stack_copy_size: 512` in CodeDefender's config — this is likely the maximum stack frame the lifter will model/copy when lifting a function. Stack frames larger than this might trigger a fallback.
- `calling_convention: WindowsAbi` — the default assumption for calls without explicit convention info.

---

### D4 — PE Parse/Emit

**Question:** How do we parse and emit PE files?

**Options considered:**
1. ❌ `object` crate for reading + custom PE writer — read via library, write custom.
2. ✅ **Fully custom PE parser + writer** — full control, no dependency boundary mismatch.
3. ❌ `goblin` + custom writer — alternative reader, same write limitation.

**Decision:** Fully custom.

**Reasoning:** A bin2bin protector needs intimate control over PE structures:
- Parse/rebuild `.pdata`/`.xdata` (RUNTIME_FUNCTION, UNWIND_INFO, C_SCOPE_TABLE) — no library provides structured access to these.
- Parse/rebuild `.reloc` (base relocations) — need full control over entry manipulation.
- Modify section table, add new sections, update data directories.
- Handle import/export tables with full fidelity.
- Preserve undocumented/quirky structures that `object` might normalize away.

The `object` crate's abstraction layer is designed for toolchain consumers (linkers, debuggers), not for tools that surgically modify binaries. Its write API creates PEs from scratch, not from a template. The impedance mismatch would cost more time fighting the abstraction than building custom.

The PE/COFF spec is well-documented (Microsoft's PE specification). The parsing/emission code is straightforward struct-level work, not algorithmic complexity. The hard parts (`.pdata`/`.xdata` semantics, relocation rebasing) are custom regardless of parser choice.

**Implications:**
- `kamy-pe` crate owns all PE parsing and emission.
- Zero-copy parsing where possible (memory-mapped file, struct overlays).
- Must handle: DOS header, PE signature, COFF file header, optional header (PE32+), section headers, data directories (import, export, relocation, exception, TLS, debug, load config, bound import, IAT, delay import).
- Must handle: `.reloc` base relocation blocks, `.pdata` RUNTIME_FUNCTION arrays, `.xdata` UNWIND_INFO + unwind codes + C_SCOPE_TABLE.

---

### D5 — Register Allocator

**Question:** What register allocation strategy?

**Options considered:**
1. ✅ **Full register allocator (linear scan)** — standard compiler approach, highest quality output.
2. ❌ Conservative spill-everything — correct but output too slow for hot code.
3. ❌ Reuse original assignment — fragile, breaks on structural transforms.

**Decision:** Full linear-scan register allocator.

**Reasoning:** BLARE2 explicitly calls out "register pressure avoidance as first-class allocator goal" and "stack-frame high-water-mark reconstruction." The Themida devirt blog goes further: **zero-spill is a hard constraint, not a soft goal.** Any spill creates a second stack frame that breaks IDA/BinaryNinja stack-arg analysis — the protected binary looks broken to every disassembler. This is a product-quality bar, not just performance.

Linear scan is the right trade: O(n) complexity, good-enough allocation quality for a protector, well-documented algorithm (Poletto & Sarkar 1999, Wimmer & Franz 2010 for SSA-based linear scan).

**Implications:**
- **Zero-spill target.** Spilling is a last resort. If the allocator can't avoid spills, the function should be flagged (not silently broken). Transforms that increase register pressure beyond available physical registers should be rejected for that function.
- Need liveness analysis across the full function CFG.
- Stack frame reconstruction from high-water mark (not from spill count).
- XMM registers must participate in allocation (Win64 ABI uses XMM0-3 for float args, XMM0-5 are volatile).
- Callee-saved register handling: if the original function saves RBX/RBP/R12-R15/XMM6-15, the allocator must respect those saves or reconstruct the prologue/epilogue.

---

### D6 — Lifter Instruction Scope

**Question:** Which x86 instructions does the lifter model semantically?

**Options considered:**
1. ❌ Core GPR subset only (~60-80 forms) — covers integer code, SSE/AVX opaque.
2. ✅ **Core GPR + basic SSE data movement** — GPR integer + MOVAPS/MOVUPS/MOVSD/MOVSS/XORPS.
3. ❌ Comprehensive (GPR + SSE + x87) — massive scope, marginal obfuscation benefit.

**Decision:** Core GPR + basic SSE data movement.

**Reasoning:** Many real functions mix integer and float code. Windows x64 ABI uses XMM0-3 for float arguments and XMM0 for float return values. If the lifter can't model XMM data movement, it can't track liveness of XMM registers across the function, which means the register allocator can't handle them, which means any function with float args is either rejected or gets wrong code.

Adding MOVAPS/MOVUPS/MOVSD/MOVSS/XORPS (zero idiom) is a small lift (~10 instruction forms) with large coverage gain. SSE *arithmetic* (ADDSS, MULPS, etc.) passes through as NativeInline — the lifter knows the instruction touches specific XMM registers (from iced-x86 metadata) but doesn't model the computation. This is sufficient for register allocation and liveness.

**Full instruction set for the lifter (v1):**

| Category | Instructions |
|----------|-------------|
| Data movement | MOV, LEA, PUSH, POP, XCHG, MOVZX, MOVSX, CDQ, CQO, CDQE |
| Arithmetic | ADD, SUB, INC, DEC, NEG, MUL, IMUL, DIV, IDIV |
| Bitwise | AND, OR, XOR, NOT, SHL, SHR, SAR, ROL, ROR |
| Comparison | CMP, TEST |
| Conditional | CMOVcc, SETcc |
| Control flow | JMP, Jcc, CALL, RET, NOP, INT3 |
| SSE data | MOVAPS, MOVUPS, MOVSD, MOVSS, XORPS |
| Misc | BSWAP, BSF, BSR, POPCNT, LZCNT, TZCNT |

Everything else → `NativeInline` with declared register/flag read/write sets (extracted from iced-x86's instruction info). Safe round-trip: the lifter records the original bytes, the codegen re-emits them verbatim, and the register allocator knows what's clobbered.

---

### D7 — SSA Form

**Question:** Proper SSA with φ-nodes or VIP-tagging (VTIL model)?

**Options considered:**
1. ✅ **Proper SSA with φ-nodes** — standard compiler SSA form.
2. ❌ VIP-tagged (VTIL model) — designed for linear VM traces, not real function CFGs.
3. ❌ Register-transfer IR (not SSA) — harder transforms, no standard literature.

**Decision:** Proper SSA with φ-nodes.

**Reasoning:** The architecture doc says "SSA via VIP-tagging, not full φ-nodes (cheaper to build from linear instruction stream)" — borrowed from VTIL. But VTIL was designed for a different problem: devirtualizing linear VM instruction traces. VM traces are mostly straight-line code with known control flow. Real function CFGs have:

- **Merge points** from if/else, loops, switch statements. Values that are live across these merges need φ-nodes.
- **The register allocator** needs liveness information at merge points. Without φ-nodes, liveness at join points is ambiguous.
- **CFF** creates entirely new control flow (switch dispatcher). Values that merge from different case arms need φ-nodes.
- **Opaque predicates** inject conditional branches. Even though they're always-true/always-false, the IR must represent them as genuine branches with merge points.

VIP-tagging works for straight-line traces but is unsound for general CFGs. This is a **correction** to the architecture doc.

Construction algorithm: Cytron et al. (1991) for φ-node insertion via dominance frontiers + iterated dominance frontier computation. Well-understood, O(n²) worst case but fast in practice. SSA destruction for lowering: conventional SSA with parallel copies at φ-nodes, coalesced during register allocation.

**Implications:**
- Need dominator tree computation (Lengauer-Tarjan or simple iterative).
- Need dominance frontier computation for φ-node placement.
- φ-nodes carry per-predecessor value operands.
- SSA destruction during lowering: insert copies for φ-node operands, let register allocator coalesce.
- Individual x86 flags (CF, ZF, SF, OF, PF, AF) as separate SSA values — φ-nodes apply to flags too when control flow merges with different flag states.

---

### D8 — Config Format

**Decision:** YAML.

**Reasoning:** CodeDefender and k0mkc both use YAML. The config needs to express ordered pass lists with heterogeneous per-pass parameters (semantics maps, bitwidth flags, iterations, probability), tagged union symbol selectors (`!Name`, `!Address`), and nested compiler settings. YAML handles this naturally; TOML's `[[array_of_tables]]` fights you on deeply nested heterogeneous structures.

`serde` + `serde_yaml` for deserialization. Config schema validated at load time.

---

### D9 — iced-x86 Dependency

**Decision:** Confirmed. Use as Cargo dependency.

**C2 justification:**
- **Maintained:** active development, 1.6K+ GitHub stars, used by k0mkc, dnSpy, numerous RE tools.
- **Not worth reimplementing:** full x86/x64 decode + encode + assemble covering thousands of instruction forms, all extensions through AVX-512. Reimplementing is person-years with zero product value.
- **API value:** instruction info (read/write regs, flags, memory operands, flow control) feeds directly into NativeInline clobber set extraction.
- **Known gotcha:** VMLAUNCH/VMRESUME/VMCALL/SYSCALL have FlowControl=Call but branch target is always 0. Wrap with `fn branch_target(instr) -> Option<u64>`.

---

### D10 — PDB Handling

**Decision:** Fork `pdb` crate for reading. Use address-map + OMAP rewriting for output (elderscroll/pdbgen pattern).

**Reasoning (updated after aftermathlabs research):** Aftermath Labs does NOT write PDBs from scratch. Their pattern is simpler:

1. Protector emits an **address-map** (old address → new address, CSV or structured format).
2. **elderscroll** (their Rust library): rewrites PDB **OMAP streams** (`omap_to_src` / `omap_from_src`) + dual section-header streams so moved code maps back to original PDB locations.
3. **pdbgen2/3**: because many debugger parsers ignore OMAP, do **partial PDB reconstruction** — rewrite symbol addresses in-place for IDA/WinDbg/x64dbg/VS compatibility.

This avoids full PDB writing (no MSF stream creation, no type merging, no DBI module reconstruction). Just: read original PDB, inject OMAP streams, patch symbol addresses.

**Read side:** fork `pdb` crate (Apache-2.0/MIT). Add:
- OMAP stream writing (elderscroll's `DbiExtraStream` layout)
- Symbol address patching (`S_PUB32`, `S_GPROC32` address fields)
- Section header stream duplication (original + new)

**No PDB required for operation.** PDB is optional input (for symbol names) and optional output (for crash debugging). Binaries without PDB are fully supported.

**Implications:**
- Fork `pdb` → `kamy-pdb`. Add OMAP write + symbol address patch.
- Emit address-map as structured output alongside the protected binary.
- elderscroll is a reference implementation for the OMAP approach.
- PDB output is a Phase 6 (Production) deliverable, not blocking the core engine.

---

### D11 — SEH/Unwind Strategy

**Decision:** Full SEH from the start — baked into the engine from Phase 2, not deferred.

**Reasoning:** SEH is a correctness non-negotiable for Windows PE. Every transformed function needs valid `.pdata`/`.xdata` entries or it will crash on any exception (including hardware exceptions like access violations, division by zero, stack overflow). Deferring SEH means:
- Every early test binary must avoid exceptions or be carefully chosen.
- Habits and shortcuts accumulate that are painful to retrofit.
- The "it works" confidence is false — it works *until* an exception happens.

CodeDefender's config has `clear_unwind_info: false` as default — they preserve/rebuild unwind info by default, only optionally strip it for anti-analysis.

**Scope:**
- Parse and rebuild `RUNTIME_FUNCTION` entries in `.pdata` for every transformed function.
- Parse and rebuild `UNWIND_INFO` with correct unwind codes for the new prologue: `UWOP_PUSH_NONVOL`, `UWOP_ALLOC_SMALL/LARGE`, `UWOP_SET_FPREG`, `UWOP_SAVE_NONVOL`.
- Parse and rebuild `C_SCOPE_TABLE` for functions using `__C_specific_handler` (SEH `__try`/`__except`/`__finally`). Scope entry addresses (`BeginAddress`, `EndAddress`, `HandlerAddress`, `JumpTarget`) must be re-pointed to new code locations.
- Handle chained `UNWIND_INFO` (`UNW_FLAG_CHAININFO`).
- Validation gate: k0mkc's 58 MSVC SEH test cases.

**Implications:**
- The lifter must track which instructions are part of the function prologue (for unwind code generation).
- The codegen must emit a valid prologue with known unwind code mapping.
- The linker must sort `.pdata` entries by `BeginAddress` (Windows requirement).
- Transforms that restructure control flow (CFF) must update C_SCOPE_TABLE entries or reject functions with SEH scopes.

---

### D12 — Verification Strategy

**Decision:** Layered — test-vector equivalence in CI, SMT proofs for rule authoring.

**Reasoning:** Two complementary layers:

1. **CI layer (always runs):**
   - Differential self-test: no-transform round-trip → functionally equivalent binary. Catches symbolization + linker bugs.
   - Per-transform test-vector equivalence: N random inputs through original and transformed code → compare register/memory state. Catches transform bugs.
   - Fast, concrete, catches real bugs.

2. **Authoring layer (offline, one-time per rule):**
   - SMT bit-vector proof per MBA rewrite rule. Proves the rule is correct for all inputs, not just tested ones.
   - `egg` (e-graph equality saturation) for MBA rule synthesis and verification.
   - `z3` (via Rust bindings) for bit-vector SMT proofs.
   - These are dev-dependencies / offline tools, not in the hot path.

**Implications:**
- `egg` is a dev/build dependency, not a runtime dependency.
- `z3` bindings as dev-dependency only. z3 itself is a large C++ library — only needed on dev machines, not shipped.
- Test-vector harness needs: function isolation (set up register/stack state, call function, capture output state), comparison logic, random input generation.

---

### D13 — V1 Pass Set

**Decision:** All five CodeDefender-observed passes: ObscureReferences, ObscureConstants, MBA, MutationEngine, LoopEncodeSemantics.

**Reasoning:** The user wants full parity with CodeDefender's public config surface from v1.

**Risk:** `LoopEncodeSemantics` is underspecified — no public documentation on what it does. Likely candidates based on the name and config shape (semantics/bitwidths/iterations):
- Encode loop iteration variables with MBA (e.g., loop counter `i` stored as MBA-encoded value, decoded each iteration)
- Encode loop-carried values (accumulator, state) with per-iteration key rotation
- Likely operates on backedge-reachable instructions in the SSA IR

Need to either reverse-engineer from CodeDefender's output or design our own loop encoding scheme. The config structure (same `semantics` and `bitwidths` fields as MBA) suggests it's MBA applied specifically to loop-carried data.

**Pass ordering (based on CodeDefender configs):**
```
ObscureReferences → ObscureConstants → LoopEncodeSemantics → MBA → MutationEngine
```
Note: ordering varies across configs. The order matters because each pass may create/consume opportunities for the next.

---

### D14 — Win32metadata Consumption

**Decision:** Pre-process `.winmd` into a compact binary format. Load once at startup. Shared across all jobs.

**Reasoning:** For a SaaS server processing many binaries, parsing `.winmd` (ECMA-335 format) per-request is wasteful. Parse once → in-memory hash map → all jobs share. For CLI, same approach: load at startup.

**Implementation:**
- Offline tool: parse `.winmd` → extract function signatures (DLL name, function name, arg count, arg types, return type, calling convention, noreturn flag) → emit compact binary format (or generate Rust source via `build.rs` with `phf` perfect hash map).
- Runtime: load into `&'static` lookup. O(1) per call-site lookup.
- Updateable: separate metadata file loadable without recompiling (better for SaaS — deploy new metadata, restart).
- Coverage: ~20K functions across ~350 DLLs (k0mkc's numbers).

---

### D15 — Delivery Model

**Decision:** CLI-first, SaaS later.

**Reasoning:** Build the engine as library crates. CLI is a thin consumer (`kamy-cli`). Validate the engine works without infrastructure overhead. SaaS wraps the same library with an HTTP API layer when the engine is proven.

**Implications:**
- All engine logic in library crates, never in `kamy-cli` directly.
- `kamy-cli` is a thin argument parser + config loader + engine invocation + output writer.
- SaaS API server will be a separate binary consuming the same crates.
- Win32metadata loaded at CLI startup (or embedded via `include_bytes!`).

---

### D16 — ELF Support Timing

**Decision:** PE-only for v1, but abstract for ELF from the start.

**Reasoning:** Only PE works in v1, but crate boundaries isolate PE-specific code in `kamy-pe`. The IR, lifter, transforms, codegen, and register allocator are format-agnostic. When ELF comes, it's a new `kamy-elf` crate + linker adjustments.

**Design constraint:** no PE-specific assumptions in:
- `kamy-core` (IR types)
- `kamy-lift` (lifter)
- `kamy-transforms` (passes)
- `kamy-codegen` (instruction selector, register allocator)
- `kamy-verify` (verification)

PE-specific code lives ONLY in `kamy-pe`, `kamy-seh`, `kamy-link`, `kamy-disasm` (function discovery heuristics may differ per format).

---

### D17 — Plugin/SDK Architecture

**Decision:** Design linker for future plugin injection capability, but defer the user-facing SDK to v2+.

**Reasoning:** CodeDefender's plugin SDK allows injecting custom C/C++ functions post-compilation (BLARE2 plugins, tether client injection). The capability falls out naturally from having a real linker that resolves symbols. Just don't invest in the SDK API, documentation, or toolchain integration for v1.

**Implication:** The linker should accept external symbol definitions and code chunks — design for it even if v1 doesn't expose it.

---

### D18 — Module-Level Settings

**Decision:** Ship all module-level settings in v1 except `ida_crasher` (deferred).

V1 module-level settings:
| Setting | Complexity | Notes |
|---------|-----------|-------|
| `custom_section_name` | Trivial | Rename the `.kamy` output section |
| `fake_pdb_string` | Trivial | Inject a fake PDB path into the PE debug directory |
| `clear_unwind_info` | Trivial | Strip `.pdata`/`.xdata` for anti-analysis (opt-in, breaks exceptions) |
| `import_protection` | Medium | IAT encryption / hashing. Requires runtime resolver stub. |
| `obscure_entry_point` | Medium | Redirect entry point through obfuscated stub |

`ida_crasher` deferred — needs IDA-specific exploit knowledge, not core product value.

---

### D19 — Crate Structure

**Decision:** Keep 12 crates as designed.

Fine-grained crate boundaries enforce modularity and enable parallel compilation. Each crate owns one concern:

| Crate | Concern |
|-------|---------|
| `kamy-core` | IR types, Link, Symbol, Chunk, AuxData |
| `kamy-pe` | PE parser/emitter |
| `kamy-disasm` | Disassembler (iced-x86 wrapper), CFG, function discovery |
| `kamy-lift` | x86 → SSA IR lifter, instruction semantics |
| `kamy-analysis` | Symbolization, register value analysis, jump tables |
| `kamy-transforms` | Obfuscation passes + optimizer passes |
| `kamy-codegen` | Instruction selector, register allocator, assembler |
| `kamy-link` | Section layout, relocation resolve, thunk placement, PE rebuild |
| `kamy-seh` | SEH/unwind: parse/rebuild RUNTIME_FUNCTION, UNWIND_INFO, C_SCOPE_TABLE |
| `kamy-verify` | Test-vector equivalence, differential self-test |
| `kamy-config` | YAML profile parsing, per-function config |
| `kamy-cli` | CLI binary |

---

### D20 — Diversification

**Decision:** Both assembler-level shuffle AND IR-level diversification pass.

Two layers of diversification:

1. **Assembler level (`assembler_settings`):**
   - `shuffle_basic_blocks`: random block ordering during encoding. Cheap, always-on.
   - `random_prefix_chance`: randomly add instruction prefixes (from CodeDefender's config).
   - Random tie-breaking in register allocation (choose equally-valid registers randomly).

2. **IR-level `DiversifyPass`:**
   - Register renaming (use different registers for equivalent computations).
   - Instruction variant selection (`add rax, 1` vs `inc rax` vs `lea rax, [rax+1]`).
   - Semantic NOP insertion (instructions that compute values never used).
   - Dead code injection with realistic data flow.

Together: per-build variance that breaks signature matching (SigBreaker model).

---

### D21 — Optimizer Passes

**Decision:** Implement all four optimizer passes from CodeDefender's config. Run to **convergence** (fixed point), not single-shot.

| Pass | Purpose | Algorithm |
|------|---------|-----------|
| `constant_propagation` | Fold known constants through the IR | Standard iterative dataflow |
| `instruction_combine` | Simplify instruction patterns (strength reduction, identity elimination) | Pattern-matching rewrite rules |
| `dead_code_elim` | Remove unused computations (especially dead flag defs from lifting) | Mark-sweep from uses |
| `prune_useless_block_params` | Remove φ-node parameters that are always the same value | SSA simplification |

**Convergence model (from BLARE2 Themida devirt blog):** passes feed each other. Const-prop enables inst-combine, which enables DCE, which enables further const-prop. Run the set iteratively until no pass makes changes. BLARE2 does this; it's the difference between clean output and bloated output.

**Key constraint:** obfuscation passes must produce optimizer-resistant output. MBA expressions like `(x ^ y) + 2*(x & y)` won't simplify under const-prop (x and y are runtime values). Opaque predicates grounded in number-theoretic invariants won't fold. The optimizer cleans up lifting artifacts and redundancy, NOT obfuscation.

---

### D22 — Rejection Handling

**Decision:** Structured rejection report (JSON/YAML) with per-function reasons.

**Rejection reason enum (initial set):**
| Reason | Meaning |
|--------|---------|
| `NoThunkSpace` | Original function too small for a thunk (< 5 bytes) |
| `BadIndirectBranch` | Unresolvable indirect jump (not a recognized jump table pattern) |
| `UnsupportedInstruction` | Instruction the lifter can't model and can't safely pass through |
| `LiftFailure` | Lifter error (e.g., malformed code, data-in-code confusion) |
| `SEHComplex` | SEH scope structure too complex for current support |
| `StackTooLarge` | Stack frame exceeds `max_stack_copy_size` |
| `SymbolizationUncertain` | Symbolization confidence below threshold |
| `CodegenFailure` | Register allocator or instruction selector failed |
| `RegisterPressure` | Transforms would require spills (violates zero-spill constraint) |

Output included in the protection report alongside transformation stats. Machine-readable for CI (assert rejection rate below threshold).

---

### D23 — Bootstrap Order

**Decision:** Bottom-up, linear dependency order.

```
Phase 1: PE parse → disasm → function discovery → container IR
Phase 2: lift → SSA construction → optimizer → codegen → assemble → link → emit PE
         (first milestone: no-transform round-trip / differential self-test)
Phase 3: obfuscation passes (one at a time, each verified before the next)
Phase 4: SEH (integrated throughout, but full test suite gate here)
```

Each stage is independently testable:
- PE parse: parse a real PE, dump sections/headers/relocations, compare to `dumpbin /all`
- Disasm: disassemble functions, compare to IDA/Ghidra
- Lift: lift one function to SSA IR, pretty-print, manually verify
- Codegen: lower SSA IR back to x86, compare to original
- Link: emit PE, load in debugger, verify sections
- Round-trip: protect with no transforms → run → compare behavior

---

### D24 — Jump Table Handling

**Decision:** Hybrid: relocations as ground truth + pattern matching + register value analysis fallback. Reject on ambiguity.

**Reasoning:** Jump tables are one of the hardest parts of binary rewriting. Entries are often relative offsets without relocations. Missing one = wrong branch target.

Three-layer approach:
1. **Relocations (.reloc):** some jump table entries have base relocations. These are ground truth — mark as known table entries.
2. **Pattern matching:** detect the standard MSVC switch pattern: `cmp reg, N; ja default; lea reg, [rip+table]; movsxd reg, [reg+idx*4]; add reg, reg; jmp reg`. Extract entry count from bounds check (N+1). Cross-reference with .pdata function boundaries (entries can't point outside the function).
3. **Register value analysis (fallback):** use the register value analysis to determine the range of the index register at the indirect jump. More general but less precise.

If none of the three layers produces a confident result → reject the function (`BadIndirectBranch`). Never guess.

**Testing:** aftermathlabs' **bintests** repo includes jump table test cases. Use as part of our test suite.

---

## Aftermathlabs Research Insights

Key findings that refined or corrected earlier decisions (full dossier: `local://aftermathlabs-research.md`):

| Finding | Impact on Design |
|---------|-----------------|
| Zero-spill is a HARD constraint (spills break disassembler stack-arg analysis) | Updated D5: register allocator must target zero spills, reject functions that can't avoid them |
| Convergence-driven optimizer (passes run to fixed point) | Updated D21: optimizer runs iteratively, not single-shot |
| PDB output via OMAP rewriting + address-map (elderscroll/pdbgen), NOT full PDB write | Updated D10: much simpler approach, fork pdb crate for read + OMAP write |
| **bintests** (86★): large PE test corpus with SEH, jump tables, corkami, >200MB | Adopt as test corpus |
| **binstats**: coverage analysis methodology (what % of functions are transformable) | Adopt for coverage metrics |
| **elderscroll**: Rust OMAP library, reference for PDB OMAP stream layout | Reference implementation for D10 |
| **pelite**: zero-alloc PE reading library they fork (we're going custom PE, but useful reference) | Informational |
| theodosius pass architecture (`pass_t`, `recomp_t`, `symbol_table_t`, `reloc_t`) | Blueprint for our pass interface |
| MBA is trivially reducible by Dna/msynth — top-tier needs stronger techniques | Informs advanced pass design (Phase 5) |
| `/GL`-compiled code breaks volatile-register ABI assumption | Correctness hazard to handle |
| llvm-msvc agent skills: free obfuscation/lifting curriculum (OLLVM, Hikari, Pluto, Arkari) | Study material for pass design |

---

### D25 — Test Corpus

**Decision:** Adopt aftermathlabs/bintests as primary test corpus.

Clone or submodule into our test suite. Run original vs protected for each binary: diff stdout + check exit code 0. Covers: SEH, corkami weird-PE, jump tables, noreturn, mutual recursion, >200MB binaries, UEFI, crypto (openssl/loki), `/O2 /GL /LTCG` and non-optimized mixes.

---

### D26 — Reproducible Diversification

**Decision:** Configurable seed + deterministic PRNG.

User sets a seed in config (default: random). All randomness derived from a deterministic PRNG (ChaCha8Rng or equivalent) seeded with that value. Same seed + same input + same config = identical output.

For parallelism determinism: per-function sub-seeds derived from `hash(global_seed, function_address)`. This ensures each function gets a unique but deterministic random stream regardless of rayon scheduling order.

---

### D27 — /GL (LTO) Binary Handling

**Decision:** Detect and warn, conservative fallback.

`/GL`-compiled (LTO) binaries may use custom calling conventions where volatile registers are preserved across calls. If we assume standard Win64 ABI clobber sets for call lifting, we get wrong code.

**Detection:** check `.drectve` section for `/GL` linker directive, or PDB compilation flags.

**Fallback:** when `/GL` detected, automatically fall back to `split_on_calls_fallback` mode (don't lift calls, treat every CALL as a full barrier). Less optimal code but correct. Report in the structured output with reason.

---

### D28 — Coverage Robustness: Depth-Adaptive Transforms (Zero-Spill Stands)

**Decision:** Single engine stays (D1). The 100%-coverage goal ("every selected function works", e.g. all of kernel32) is met by adapting transform intensity to the register budget, **not** by adding a spill path.

Per-function ladder:
1. Requested passes at full intensity; if regalloc fails `RegisterPressure`, retry at reduced intensity (fewer MBA iterations, no CFF intermediates) — deterministic per D26 sub-seed.
2. If even identity lowering doesn't fit → relocation fallback, reported via D22.

**Reasoning:** measured on target.exe (2026-10-16): 95/169 functions reach regalloc with the callee-saved pool; the remaining 70 exceed 15 GPRs under zero-spill. D5's bar exists because spill frames break disassembler stack analysis — a product-quality constraint. Depth adaptation keeps every output disassembler-clean while still protecting pressure-heavy functions at reduced depth, which is strictly better than either spilling or rejecting.

**Implications:**
- Callee-saved activation (Phase 4) is the first rung: widens the pool from 8 volatile to 15 GPRs + XMM6-15.
- XMM registers must fully participate in allocation (D5 implication).
- Passes need an intensity parameter so the retry ladder can degrade deterministically.
- Encode bugs (XMM5 mem-operand) fixed independently.

---

### D29 — Trampoline Stub Obfuscation

**Decision:** Thunk stubs get deterministic per-function flavor diversification + junk fill in scrubbed body bytes; direct-call re-pointing eliminates stubs entirely where all callers are symbolized with confidence.

- Flavor set (per-function choice from a D26 sub-seed; must fit the original function size; `E9 rel32` stays the 5-byte floor / NoThunkSpace boundary):
  - `E9 rel32` — plain near jump (floor)
  - `FF 25 00000000 + qword target` — RIP-indirect through a pointer
  - `B8 imm32 + FF E0` / `49 BB imm64 + 41 FF E3` — mov-reg + jmp-reg
- Scrubbed original-body bytes get junk/dead padding instead of int3-only.
- When every direct caller of a moved function is itself moved or re-pointable with confidence, re-point the calls and drop the stub — the best-hidden stub is no stub. Below confidence threshold the stub stays (graceful degradation, never correctness-dependent).
- Encrypted/validated dispatch tables are deferred to the runtime (D30): `jmp [rip+x]` with the pointer materialized by init code.

**Reasoning:** ground truth (RE of CodeDefender `HelloWorld-Injected.exe`, 2026-10-16): the demo ships verbatim `E9 rel32` detours on every protected entry ("no obfuscation applied for ease of analysis"). Even the commercial model leaves plain stubs when the knob is off — stub stealth is a cheap differentiator implemented at thunk-emission time, orthogonal to D2 correctness.

---

### D30 — Runtime Section, EP Hijack & Plugin SDK (enriches D17)

**Decision:** Adopt the CodeDefender runtime/injection model: kamy ships a runtime component inside the protected binary, and the plugin SDK (D17 "v2+") takes the CodeDefender SDK shape.

Ground truth (RE of `HelloWorld-Injected.exe`, `.belabs` sections, base 0x140000000; codedefender-io/plugins README):
- **EP hijack:** `AddressOfEntryPoint` redirected to a generated stub that walks an init-callback table (bounds in RW section), `__fastfail`s on nonzero status, then tail-calls the original CRT entry (`[[clang::musttail]]` in their SDK).
- **Runtime sections:** RX code + RW mutable state + R rodata (their split @0x7000/0x8000/0x9000). Helpers: PEB InLoadOrderModuleList walk + export hashing (lazy_importer-style manual import resolution), cpuid/xgetbv feature init (codegen-variant dispatch), fastfail/RtlCaptureContext integrity reporter.
- **Plugin SDK:** user C/C++ compiled with LLVM-MSVC against SDK headers; `init_table_start/end` linker symbols register init functions; the linker ingests the resulting COFF. This is D17's "linker accepts external symbol definitions and code chunks" made concrete.

**Implications:**
- kamy-link needs COFF object ingestion (sections, symbols, COMDAT, relocations).
- Config: plugin object list per profile; init ordering deterministic.
- EP hijack must preserve TLS callback ordering and CET compatibility (ties into Phase 4).
- Their old-`.pdata`→`.text` repurposing is space reclamation (D2 option 2) — evidence the commercial tool reclaims section space; stays deferred for us.
- Open external RE threads: confirm `sub_140007000` (import resolver vs anti-tamper); enumerate the full trampoline set (5 verified: 0x1000, 0x1070, 0x10c0, 0x17c8, 0x1d54); inspect init callbacks at `.rdata` 0x27f0.

---

### D31 — Phase Reordering: Unwind Kernel into Phase 2; SEH before Obfuscation

**Decision:** The unwind-correctness kernel moves into Phase 2; full SEH (was Phase 4) runs before Obfuscation Passes (was Phase 3).

1. **Phase 2 completion set** (pulled from the old Phase 4):
   - Callee-saved activation: wire isel push/pop emission, RSP 16-byte alignment shim (odd push count flips entry parity), and drop the redundant live-through `Use` pins for the 9 callee-saved GPRs in `lift_ret` — push/pop owns preservation, so those chains no longer need to be live through the body (major register-pressure relief, D5 untouched).
   - `.pdata`/UNWIND_INFO emission describing our *generated* prologues for plain (non-EH) functions. Without it, any stack walk through a moved function (exceptions, ETW, debuggers) reads garbage.
   - XMM5 mem-operand encode fix (4 functions).
   - D28 pressure ladder once the above land.
   - Gate: identity SSA round-trip ships real functions through SSA, differential-verified (kamy-verify: original vs protected, stdout + exit code).
2. **New order:** Phase 3 = SEH & CET in full (scope tables, handler re-pointing, CET reconciliation, MSVC test suite — SEHComplex functions stay rejected until then); Phase 4 = Obfuscation Passes.

**Reasoning:** Correctness before transforms. No obfuscation pass is verifiable while the SSA backend ships 0/169 and silently falls back to relocation — the differential harness would test the fallback, not the transform. D11 already mandated SEH "baked in from Phase 2"; the kernel split realizes that without dragging the whole SEH suite into Phase 2. D23's stage order (parse → disasm → lift → codegen → link) is untouched.

**Implications:**
- Functions with SEH handlers (`SEHComplex`) remain out of scope for obfuscation until Phase 3 lands.
- Win32metadata (D14) stays deferred: over-approximated call args are correctness-neutral (conservative), pressure-negative only.

### D32 — Error handling & observability

**Decision:** Standardize errors on `anyhow` across all crates — remove the
`thiserror` enums `ConfigError`, `PeError`, `CodegenError`, and `LinkError` — and
standardize diagnostics on `tracing` with a dedicated `kamy-observe` crate owning
a terminal-first `tracing-subscriber` stack (compact/tree/json formats,
`EnvFilter` via `KAMY_LOG`). `RejectionReason` remains structured domain data
(**D22**), distinct from errors.

**Reasoning:** the workspace is one application split into crates, not a public
library surface, so typed error enums bought matching that no caller used — every
caller either propagated or counted rejects. `anyhow` removes the per-crate error
boilerplate while `.context()` preserves the failure chain. Degradation and
rejection are first-class product signals (**D28** pressure ladder, **D22**
rejects): routing them through leveled, per-scope `tracing` lets an operator or
agent see exactly which layer degraded or failed without scattering `println!`.
tracing + tracing-subscriber + tracing-tree are the de-facto Rust standard and
pass **C1/C2**.

**Implications:**
- New `kamy-observe` crate (format-agnostic, **D16**); every engine crate
  depends on `tracing`.
- `kamy-cli` installs the subscriber and reserves stdout for results.
- `RejectionReason` is explicitly not an error type.
- Severity split: pass/transform degradation at `warn`; milestone counts and the
  per-reason reject aggregate at `info`; individual per-function rejects and
  moves at `debug`; per-instruction detail at `trace`.

## Decision Summary

| # | Decision | Choice |
|---|----------|--------|
| D1 | Engine model | Single SSA IR engine, pass-selectable |
| D2 | Linker strategy | Thunk at original site + new .kamy section |
| D3 | CALL handling | Lift calls + split-on-call fallback |
| D4 | PE parse/emit | Fully custom (kamy-pe) |
| D5 | Register allocator | Linear scan, zero-spill hard constraint |
| D6 | Lifter scope | Core GPR + basic SSE data movement (~70 forms) |
| D7 | SSA form | Proper SSA with φ-nodes |
| D8 | Config format | YAML |
| D9 | iced-x86 | Confirmed as Cargo dependency |
| D10 | PDB handling | Fork pdb crate + OMAP rewriting (elderscroll pattern) |
| D11 | SEH/unwind | Full SEH from the start (Phase 2) |
| D12 | Verification | Test-vectors in CI + SMT for rule authoring |
| D13 | V1 passes | All five: ObscureRef, ObscureConst, MBA, Mutation, LoopEncode |
| D14 | Win32metadata | Pre-process, load once at startup, shared across jobs |
| D15 | Delivery model | CLI-first, SaaS later |
| D16 | ELF timing | PE-only v1, abstract for ELF from the start |
| D17 | Plugin/SDK | Linker capable, SDK deferred to v2+ |
| D18 | Module settings | All except ida_crasher in v1 |
| D19 | Crate structure | 12 crates as designed |
| D20 | Diversification | Assembler shuffle + IR-level diversify pass |
| D21 | Optimizer | All four passes, convergence-driven (fixed point) |
| D22 | Rejection | Structured report (JSON/YAML) with reason enum |
| D23 | Bootstrap | Bottom-up linear: PE → disasm → lift → codegen → link |
| D24 | Jump tables | Hybrid: relocs + pattern match + register value analysis |
| D25 | Test corpus | Adopt aftermathlabs/bintests |
| D26 | PRNG | Configurable seed, deterministic ChaCha8Rng |
| D27 | /GL handling | Detect and warn, fall back to split-on-calls |
| D28 | Coverage robustness | Depth-adaptive transforms; zero-spill stands |
| D29 | Stub stealth | Flavor diversification + junk fill + direct-call re-pointing |
| D30 | Runtime & plugin SDK | CodeDefender model: EP hijack, init table, COFF plugins (D17 enriched) |
| D31 | Phase order | Unwind kernel into Phase 2; SEH before obfuscation |
| D32 | Error handling & observability | anyhow everywhere (no thiserror); tracing via kamy-observe; KAMY_LOG scope/level; RejectionReason stays domain data |

---

## Open Questions

Implementation-detail level (resolve during build, not blocking architecture):

- Container IR Rust type design (concrete struct layouts)
- Instruction selector implementation (table-driven vs pattern matching)
- Thread safety model for rayon parallelism (what's shared, what's per-function)
- SaaS architecture (when the time comes)
- LoopEncodeSemantics reverse-engineering or original design
