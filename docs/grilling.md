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

**2. Own linker with reference rewriting and space reclamation.**

The windows README states *"our linker will reuse free space."* Historical `NoThunkSpace` benchmark output is not evidence for a universal per-function thunk model. Newer sample analysis in [#17](https://github.com/mkxto/kamy/issues/17) records 953 direct branches to moved code, 26 base relocations (none into moved code), and 10 residual unwind-referenced stubs. D37 supersedes the original thunk inference.

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
- `LoopEncodeSemantics` — loop-body encoding of {add, sub, and, xor}, same config shape (narrower op set than MBA)

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

### D2 — Linker Strategy (superseded by D37)

**Original choice:** original-VA thunk + appended `.kamy`, with reclamation deferred and a five-byte minimum function size.

**Superseded:** [#17](https://github.com/mkxto/kamy/issues/17) and [#27](https://github.com/mkxto/kamy/issues/27) authorize complete reference rewriting and PE rebuild. Rewriting inbound references is required for correctness, not an optional direct-call optimization. No per-function entry thunk, `NoThunkSpace` floor, original-VA retention, or blanket `int3` scrub remains in the target design. See D37 for conservative residency and selective reclamation rules.

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

### D5 — Register Allocator (revised by D40)

**Decision:** D40 supersedes the original zero-spill prohibition. The backend
uses memory-backed intermediates and bounded scratch working sets in one
concrete frame. Pressure MUST NOT reject otherwise supported functions or
reduce requested intensity. Actual-body unwind describes the real frame.
Handoff 2 implements this cutover; the former pressure ladder is historical
handoff-1 behavior, not an active fallback. Evidence is in [STATUS.md](STATUS.md).

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

**Resolved (was underspecified).** `LoopEncodeSemantics` encodes a single binary
operation (`add`, `sub`, `and`, `xor`) as an iterative loop computing the same
result by carry/bit propagation, so the native op never appears in the output.
Confirmed from a protected sample: `a + b` lowers to a ripple-carry adder
(`carry = a&b; a = a^b; b = carry<<1;` looped until `b == 0`, XOR emitted as
`(a|b)-(a&b)`). The op set is narrower than MBA — `{add, sub, and, xor}` only, no
`or`/`not`/`neg`. See research.md §2.8. The earlier guess (MBA applied to
loop-carried data) was wrong: the loop *is* the operation, not a wrapper around
existing loops.

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

**Decision:** Authored-module linking follows D38. D39 supersedes the original public-SDK deferral with a configurable Rust-only SDK/plugin system.

**Reasoning:** The vendor's [Module Extension System](https://codedefender.io/blog/2025/03/27) is the static-linking reference, not a requirement to support every vendor source language. Kamy plugins are authored and built in Rust; native object files are compiler intermediates, not a public C/C++ plugin interface.

**Implication:** Consume specialized DLL code/data symbols and exact authored relocations. Keep plugin compilation and injection separate from host protection.

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

**Rejection reasons:** safe rejection remains binding. Current frame failures
describe semantic proof or explicit resource limits, not register pressure.
| Reason | Meaning |
|--------|---------|
| `BadIndirectBranch` | Unresolvable indirect jump |
| `UnsupportedInstruction` | Instruction neither modeled nor safely passed through |
| `LiftFailure` | Lifter failure, such as malformed code |
| `SEHComplex` / `EhNoBucketCreation` | Unsupported EH structure or unproved generated unwind bucket |
| `StackTooLarge` | Configured stack-copy bound exceeded |
| `SymbolizationUncertain` | Insufficient reference/symbolization evidence |
| `CodegenFailure` | Structured code-generation failure |
| `FrameDynamic` | Logical RSP depends on an unproved runtime value |
| `FrameConflict` | Reachable stack states disagree or violate call/return contracts |
| `FrameOverflow` | Frame arithmetic or displacement is not representable |
| `FrameResourceLimit` | Concrete frame exceeds the 16 MiB implementation bound |

`NoThunkSpace`, `RegisterPressure`, caller-frame and self-recursion exclusions
are retired, not current rejection choices. The report retains actual reasons
for unsupported native/ISA/EH cases; memory homes do not prove those semantics.

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
2. **Pattern matching:** per-function use-def DAG + `petgraph` VF2 subgraph isomorphism, not textual instruction matching (research.md §10.5). Recognize MSVC/LLVM dispatch variants and derive a proven entry count from a bounds check or mask. Cross-reference with function boundaries; ambiguous or out-of-function targets reject.
3. **Register value analysis (fallback):** use the register value analysis to determine the range of the index register at the indirect jump. More general but less precise.

If none of the three layers produces a confident result → reject the function (`BadIndirectBranch`). Never guess.

Recovered switches become intra-function CFG edges and lower table-free through SSA. No table is patched, copied, or re-emitted; an untouched/rejected host function retains its original table. See [#18](https://github.com/mkxto/kamy/issues/18), [#19](https://github.com/mkxto/kamy/issues/19), and research.md §10.4–10.5.

**Testing:** aftermathlabs' **bintests** repo includes jump table test cases. Use as part of our test suite.

---

## Aftermathlabs Research Insights

Key findings that refined or corrected earlier decisions (full dossier: `local://aftermathlabs-research.md`):

| Finding | Impact on Design |
|---------|-----------------|
| Zero-spill observations concern devirtualization, not a universal protector constraint | D40 adopts the measured protector's memory-backed model; the earlier D5 prohibition is superseded |
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

### D28 — Coverage Robustness (revised by D40)

**Decision:** One SSA engine, one memory-backed backend, one concrete frame and
one link plan. Lower supported functions once at requested intensity; identity
reports zero actual transformation. No pressure-driven intensity ladder and no
verbatim relocation fallback. Genuinely unmodeled semantics/references still
fail closed with their specific reasons. H1 ladder measurements remain
historical evidence, not the current policy; see [STATUS.md](STATUS.md).

---

### D29 — Trampoline Stub Obfuscation (superseded by D37)

**Original choice:** diversify original-site thunk flavors and junk-fill vacated bodies; remove stubs only when direct callers were known.

**Superseded:** the clean cutover removes this mechanism, its five-byte floor, and its encrypted dispatch-table extension. The earlier claim that `HelloWorld-Injected.exe` places an `E9` detour on every protected entry was incorrect: that sample demonstrates module injection with no transforms, not a universal thunk strategy ([vendor README](https://github.com/codedefender-io/plugins), [#17](https://github.com/mkxto/kamy/issues/17)). D26 deterministic diversification remains independent of entry thunks.

---

### D30 — Runtime Section, EP Hijack & Plugin SDK (superseded by D38)

**Original choice:** mandatory runtime, generated init-table EP stub, COFF-only plugin ingestion, and deferred section recycling.

**Superseded:** D38 distinguishes optional injected module code/data from transformation and gives the target-specific entry ABI. RW sections are module data, not proof of a generic runtime or injection. The vendor module is a specialized DLL with unmerged data directories, not a COFF-only input. The shipped EXE's original entry is the final callback **inside** `[begin,end)`; the published source's past-`end` `musttail` call is unreachable because that entry does not return. It is not a continuation to reproduce. The published loader cannot front returnable `DllMain` unchanged ([#32](https://github.com/mkxto/kamy/issues/32), [#35](https://github.com/mkxto/kamy/issues/35)). Section recycling is part of #27, not deferred under D2.

---

### D31 — Phase Reordering: Unwind Kernel into Phase 2; SEH before Obfuscation

**Historical scheduling record:** the completion set and measurements below
describe the pre-D40 backend. D40/H2 supersede its push/pop allocation design
and pressure ladder. They do not establish current ISA or full EH acceptance.

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
rejection are first-class product signals (**D22**, with the former **D28**
pressure ladder now historical): routing them through leveled, per-scope `tracing` lets an operator or
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

### D33 — Runnable differential corpus (issue #7)

**Decision:** Golden record, blessed from the original. `kamy corpus verify` compares the protected binary to a committed per-member record; the original is executed only during `--bless` (run N times with seeded inputs, determinism-checked) and the record carries os/arch/toolchain provenance. The corpus lives in `github.com/mkxto/kamy-corpus`, referenced by a loose `--corpus <dir>` / `KAMY_CORPUS_DIR` and pinned for reproducibility by a committed `corpus.lock` (url + commit sha). It is an open verification tool, deliberately NOT a blocking CI gate (deferred); issue #7's CI-gate acceptance is explicitly left open.

### D34 — Per-member oracle

**Decision:** Each member declares an oracle. `console` = exit code + stdout + stderr. `gui` = an ordered API-call trace of call names + STRING arguments only (minimal trace: no numeric/pointer/flag capture), captured by a build-time winapi link-shim (NO runtime DLL injection) that emits to a sidecar trace file and suppresses the blocking side effect. `dll` = results of a loader host that `LoadLibrary`s the binary by path and calls a curated set of pure, self-contained exports; impure/stateful exports stay static-only. This turns kernel32-class binaries from static-reparse-only into actually-executed for their pure exports — the blind spot issue #7 names.

### D35 — Two-phase build

**Decision:** `kamy corpus build` compiles members from per-member recipes (MSVC `cl` via `vcvars64.bat`, `clang-cl`, `rustc`) on a toolchain-equipped host; `kamy corpus verify` consumes prebuilt binaries + golden and needs no compilers. Members must be deterministic-by-construction; a non-deterministic original is quarantined at bless. An absent toolchain (e.g. clang-cl) skips its members with a warning rather than failing.

### D36 — kamy-corpus crate

**Decision:** A new workspace crate `kamy-corpus` owns the manifest, build driver, bless, verify loop, and the DLL loader. `kamy-verify` keeps the format-agnostic record/compare/run primitives. Windows-specific execution (vcvars build, loader FFI) is cfg-gated so the core still compiles cross-platform.

### D37 — Complete Reference Rewriting & PE Rebuild

**Decision:** Adopt the user-authorized [#17](https://github.com/mkxto/kamy/issues/17) target. This supersedes D2, D29, D22's `NoThunkSpace` choice, and D28's verbatim relocation/100%-host-coverage fallback. These are target requirements, not implementation or verification claims.

- [#18](https://github.com/mkxto/kamy/issues/18) gates movement with a complete per-function incoming/outgoing reference model: decoded direct branches, RIP-relative references, relocation-backed absolute pointers, known RVA fields, recovered switch CFG edges, unwind boundaries, entry, and export/TLS/load-config/debug metadata. Host inference is conservative; unresolved consumers pin their targets. Do not guess completeness from a confidence score or the absence of `.reloc` entries. Safe-reject stays (D22).
- [#19](https://github.com/mkxto/kamy/issues/19) rewrites rel32/RIP-relative displacements in both directions, including resident callers of moved functions. These references have no loader fixup and are the main x64 mechanism. Recovered switches lower table-free (D24); untouched tables stay untouched.
- [#20](https://github.com/mkxto/kamy/issues/20) regenerates `.pdata`/`.xdata`, including generated frame/unwind semantics and supported EH scopes. [#30](https://github.com/mkxto/kamy/issues/30) rebases relocation-backed VA64 fields and rebuilds matching loader fixups. It does not rewrite switch tables.
- [#22](https://github.com/mkxto/kamy/issues/22) translates known residual taken addresses only where the consumer can use that translation. A translation map alone cannot fix opaque consumers; keep their targets resident. Retire per-function entry thunks and `NoThunkSpace`, not safe-reject.
- [#27](https://github.com/mkxto/kamy/issues/27) makes `.kamy` the selected/lowered code home, with PIC code where possible, rebuilt Import/Debug/BaseReloc/Exception directories, and recycled/retyped empty section slots. No original-VA thunk or `0xCC` thunk-flood. Selective builds reclaim interior holes in place and truncate only a dead tail; do not slide pinned survivors. Whole-image compaction requires rebasing every affected survivor and is not implied by selective reclamation.
- [#33](https://github.com/mkxto/kamy/issues/33) defaults to a **non-enforcing, internally consistent CFG/LoadConfig**: valid cookie references, non-enforcing check/dispatch targets, and cleared function-table-present state or valid remaining metadata. Real enforcing module CFG is a vendor claim and later opt-in, not a gate here.

D40 supersedes D5's zero-spill restriction. D16 format-agnostic core, D22 safe rejection, and D24 use-def DAG + `petgraph` VF2 recovery/table-free lowering remain binding. PE directory interpretation belongs in PE-specific crates; shared reference kinds carry no PE layouts. Corpus/runtime acceptance in the linked issues remains required; this decision records no exercised proof.

### D38 — Authored Modules, Entry ABI & Optional Presentation

**Decision:** Supersede D30's mandatory-runtime, COFF-only, and past-`end`-tailcall claims with the [vendor Module Extension System](https://codedefender.io/blog/2025/03/27) and [published plugin source](https://github.com/codedefender-io/plugins), as scoped by [#32](https://github.com/mkxto/kamy/issues/32) and [#35](https://github.com/mkxto/kamy/issues/35).

- Host code is inferred from an already-linked image and may be safely rejected. Kamy-authored Rust modules have dedicated DLL data-directory ownership; compiler-authored symbols and relocations enter the same shared model and final rebuild. Exact reference provenance does not waive instruction, explicit ABI, frame or unwind correctness. D40 supersedes the former zero-spill restriction and second module rebuild.
- EP redirection and moving the original startup are independent. A transform-only returnable DLL entry points directly into `.kamy` and returns to the loader; exports are rebased and DLL header semantics preserved. Kernel EP stays pinned and untouched. EXE startup may remain resident or move according to resolved references.
- Injection is optional, per-build, **off by default and off for kernel entries**. Preserve entry arguments, TLS ordering, stack/return ABI, and CET semantics. For an EXE init table, the final in-range original entry must not return; never execute a past-`end` slot. For DLL payloads, sequence a payload then tail-transfer to `DllMain`, preserving entry arguments and its return value, or explicitly exempt the final entry from status checking. Never interpret `DllMain`'s successful `TRUE` as a failed init status.
- Section naming/blanking/rebranding is optional, per-build, **off by default** ([#34](https://github.com/mkxto/kamy/issues/34)); `.kamy` remains the normal name. Neither names nor payload injection are prerequisites for relocation correctness. The original public-SDK deferral is superseded by D39.

Vendor claims about enforcing CFG, longjmp/SAFESEH registration, and unwind-safe syscalls are not measured sample behavior and do not expand this epic's gates.

### D39 — Configurable Rust SDK & Plugins

**Decision:** The user promotes a reusable SDK/plugin system into this epic and explicitly limits plugin authoring to **Rust**. No C/C++ SDK, headers, templates, or supported plugin workflow.

- A `no_std` Rust SDK defines a Win64 `extern "system"` callback receiving the original three entry arguments and returning a zero-success status. Rust's native compiler/linker outputs do not imply support for another authoring language.
- A Cargo-based build command produces a specialized DLL with dedicated data-directory sections and versioned embedded code/data/reference metadata, derived from compiler-authored native COFF relocations and symbols. DLL consumers do not need object sidecars or host inference. This preserves D38's module model rather than replacing it with a COFF-only consumer.
- YAML opts into an ordered list of named plugin artifacts, with paths relative to the profile. Loader mode is configurable. Qualified `plugin::symbol` names select the same transform passes as host code. No built-in payload, runtime DLL loading, or plugin execution inside the protection tool.
- D16 crate boundaries, D37 reference rewriting and D38 target-specific entry/unwind/TLS/CET contracts remain binding, as revised by D40. Unsupported module constructs fail contextually; never omit a callback or verbatim-relocate rejected module code.

### D40 — Ordered Native Rebuild and Rust SDK Repair

**Decision:** The confirmed campaign in `handoffs/00-master.md` supersedes
incompatible implementation restrictions in D5, D28 and D37–D39.

- Handoff 1 establishes stable source-qualified symbols and symbolic
  expressions, explicit authored-call contracts, and one final layout/rebuild
  for host code, module code/data and generated helpers. Numeric namespaces,
  MOVABS byte normalization and a second host/module rebuild are not contracts.
- Rust plugin builds may require version-matched LLVM tools to obtain
  authoritative machine ABI metadata. Metadata must describe the exact emitted
  native code; unvalidated diagnostic text, mangled names and guessed Win64
  defaults are not substitutes for validated contracts. Rust-only authoring remains.
- Handoff 2 implements concrete frames and memory-backed intermediates with
  bounded scratch sets and explicit flags. Pressure/caller-frame/self-recursion
  exclusions and intensity retries are retired. One actual frame and backend
  preserve original outgoing storage and incoming coordinates; unwind describes
  that real frame. Specific dynamic/conflict/overflow/resource failures remain.
- Handoff 3 integrates compiled Rust startup, ordinary imports and Rust `std`
  with `panic=abort`. DLL initialization runs only on process attach, before
  the original entry. No hidden worker/deferred-init workaround.
  It MUST consume H2 concrete-frame/ABI/unwind interfaces and regression
  fixtures without introducing duplicate conventions. H3 remains pending;
  current generated startup is intentional H1 behavior, not compiled std support.
- Handoff 4 adds whole-image virtual compaction to the same link plan, or
  fails specifically when global placement cannot be justified. Selective
  reclamation and raw repacking are not whole-image compaction.
- Preserve the existing MBA baseline. Honor supported requests in declared
  order and reject unsupported settings explicitly. Identity suppresses
  semantic passes, not configured injection, naming or layout policy.
- Conservative host reference completeness, no original-entry thunks, no
  verbatim relocation, and D16/D22/D24 remain binding. These decisions are
  target contracts, not claims that later handoffs are implemented or verified.



## Decision Summary

| # | Decision | Choice |
|---|----------|--------|
| D1 | Engine model | Single SSA IR engine, pass-selectable |
| D2 | Linker strategy | Superseded by D37: reference rewriting, no original-VA thunks |
| D3 | CALL handling | Lift calls + split-on-call fallback |
| D4 | PE parse/emit | Fully custom (kamy-pe) |
| D5 | Register allocator | D40: concrete frames, memory-backed baseline, bounded scratch working sets |
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
| D17 | Plugin/SDK | D38 authored linking; D39 configurable Rust-only public SDK |
| D18 | Module settings | All except ida_crasher in v1 |
| D19 | Crate structure | 12 crates as designed |
| D20 | Diversification | Assembler shuffle + IR-level diversify pass |
| D21 | Optimizer | All four passes, convergence-driven (fixed point) |
| D22 | Rejection | Structured safe-reject; `NoThunkSpace` retired by D37 |
| D23 | Bootstrap | Bottom-up linear: PE → disasm → lift → codegen → link |
| D24 | Switch recovery/lowering | Relocs + use-def DAG/petgraph VF2 + value analysis; table-free lowering |
| D25 | Test corpus | Adopt aftermathlabs/bintests |
| D26 | PRNG | Configurable seed, deterministic ChaCha8Rng |
| D27 | /GL handling | Detect and warn, fall back to split-on-calls |
| D28 | Coverage robustness | One requested-intensity attempt; specific safe rejects, no pressure ladder or verbatim fallback |
| D29 | Stub stealth | Superseded by D37; no per-function entry stubs |
| D30 | Runtime & plugin SDK | Superseded by D38; optional authored modules, entry-ABI-specific redirection |
| D31 | Phase order | Unwind kernel into Phase 2; SEH before obfuscation |
| D32 | Error handling & observability | anyhow everywhere (no thiserror); tracing via kamy-observe; KAMY_LOG scope/level; RejectionReason stays domain data |
| D33 | Runnable corpus | Golden record blessed from original; open tool, no CI gate |
| D34 | Per-member oracle | console stdio / gui link-shim trace / dll loader over pure exports |
| D35 | Two-phase build | `corpus build` needs toolchains; `corpus verify` does not |
| D36 | kamy-corpus crate | Orchestration crate; kamy-verify stays format-agnostic |
| D37 | Relocation rebuild | Complete references, conservative host residency, no thunks, selective reclamation, consistent non-enforcing CFG |
| D38 | Modules & entry ABI | Exact authored-module refs; returnable DLL EP direct, kernel EP pinned; injection/names optional |
| D39 | Rust SDK/plugins | Cargo-built exact metadata modules, ordered opt-in injection, no C/C++ support |
| D40 | Repair campaign | Unified symbols/rebuild, authoritative Rust ABI metadata, memory-backed lowering, std/runtime, global compaction in ordered handoffs |

---

## Open Questions

Implementation-detail level (resolve during build, not blocking architecture):

- Container IR Rust type design (concrete struct layouts)
- Instruction selector implementation (table-driven vs pattern matching)
- Thread safety model for rayon parallelism (what's shared, what's per-function)
- SaaS architecture (when the time comes)
- ~~LoopEncodeSemantics reverse-engineering or original design~~ — resolved: encode add/sub/and/xor as carry/bit-propagation loops (research.md §2.8, D13)
