# Kamy — Architecture & Design

Binary-to-binary protection engine. 100% Rust.
Composable, per-function, per-layer protections with scriptable configuration.
Targets Windows x86-64 PE32+ only. x86/PE32 support is explicitly out of scope; no 32-bit pipeline is planned. ELF and ARM64 remain future targets.

This document specifies the approved target, not completed implementation or verification. The relocation cutover is [#17](https://github.com/mkxto/kamy/issues/17), governed by grilling D37–D38; those decisions supersede D2/D29/D30's original-VA thunk/runtime assumptions.

---

## 1. System Overview

```
┌────────────────────────────────────────────────────────────────┐
│                        kamy pipeline                           │
│                                                                │
│  ┌──────────┐   ┌──────────┐   ┌───────────┐   ┌───────────┐  │
│  │ Analyze  │──▶│   Lift   │──▶│ Transform │──▶│  Rebuild  │  │
│  │          │   │          │   │           │   │           │  │
│  │ PE parse │   │ Disasm   │   │ Mutation  │   │ Codegen   │  │
│  │ .pdata   │   │ CFG      │   │ MBA       │   │ Assembler │  │
│  │ .reloc   │   │ SSA IR   │   │ CFF       │   │ Linker    │  │
│  │ PDB      │   │ Symbols  │   │ OP/Const  │   │ PE emit   │  │
│  │ imports  │   │ Links    │   │ Diversify │   │ .pdata    │  │
│  └──────────┘   └──────────┘   └───────────┘   └───────────┘  │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                  Protection Profile                      │  │
│  │  Per-function layer selection via TOML/script config      │  │
│  └──────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────┘
```

## 2. Single SSA IR Engine

One pipeline for all protection levels. Every transformed function goes through:

```
Lift → SSA IR → Obfuscation Passes → Optimize → Compile → Link
```

Protection depth is controlled by **pass selection**, not by choosing a different engine.
A "light" profile runs fewer/simpler passes on the same IR as a "heavy" profile.

**Observed CodeDefender pass types** (from public configs):
- `ObscureReferences` — hide cross-references
- `ObscureConstants` — hide constant values
- `MixedBooleanArithmetic` — MBA with configurable semantics/bitwidths/iterations/probability
- `MutationEngine` — instruction mutation (SSE-aware), same config shape
- `LoopEncodeSemantics` — encode `add`/`sub`/`and`/`xor` as an iterative loop (ripple-carry / per-bit)

**Compiler settings** (always present, not opt-in):
- Lifter: `lift_calls`, `calling_convention`, `max_stack_copy_size`, `split_on_calls_fallback`
- Optimizer: `constant_propagation`, `instruction_combine`, `dead_code_elim`, `prune_useless_block_params`
- Assembler: `shuffle_basic_blocks`, `instruction_prefix`, `random_prefix_chance`

**Properties:**
- Per-function selection via symbol names, patterns, addresses, PDB symbols.
- Per-function host safe-rejection with structured reasons (`BadIndirectBranch`, unresolved references, unsupported lowering). No `NoThunkSpace` in the target.
- Unselected/rejected host bodies stay resident, but their known references into moved code MUST still be rewritten. They are not globally byte-untouched.
- Lift/transform/codegen is per-function parallel; the complete reference model and final layout/rewrite are shared coordination boundaries.
---

## 3. IR Design

Two-layer IR, informed by VTIL, GTIRB, and Egalito.

### Layer 1 — Relocatable Container IR (rewriting substrate)

```
Program
  └── Module (one PE/ELF)
        ├── Section[]
        │     └── Chunk[] (CodeChunk / DataChunk)
        │           └── Instruction[]
        ├── Symbol[]
        ├── Link[] (symbolic references — the core correctness mechanism)
        ├── Relocation[]
        └── AuxData (analysis results, unwind info, jump tables, metadata)
```

**Key invariant:** layout-sensitive references are symbolic, not untracked absolute addresses. Movement is permitted only after reference completeness and rewriteability are established (D37). Opaque consumers pin their targets; a symbolic overlay alone does not prove arbitrary host code movable.

**SymbolicExpression overlay:** every operand that could be a reference carries a typed symbolic annotation: `Absolute(symbol, offset)`, `PcRelative(symbol, offset)`, `LabelDiff(sym1, sym2, offset)`. Classified per KAIST Type I-VII taxonomy.

### Layer 2 — SSA Semantics IR (analysis/transform substrate)

```
Function
  └── BasicBlock[]
        ├── φ-nodes: Vec<Phi>  (one per value merging from predecessors)
        └── Instruction[]  (SSA form)
              ├── opcode: IrOp
              ├── operands: Vec<Value>  (SSA values)
              ├── flags: FlagSet  (individual flag SSA values: CF, PF, ZF, SF, OF, AF)
              └── memory: MemoryRef  (symbolic, width-typed)
```

**Design rules:**
- Proper SSA with φ-nodes (Cytron et al. construction via dominance frontiers). Required for correct liveness analysis on real function CFGs with merge points.
- Keep native ISA concrete. Unmodeled x86 instructions pass through as opaque `NativeInline` nodes with declared register/flag read/write sets.
- Symbolic expression trees, copy-on-write, O(1) hash in constructor.
- Thread-local simplifier caches (no global lock).
- Relocations/casts are opaque leaves in expression trees — never folded.
- Known/unknown bit-vector abstract domain for sound dead-bit elimination.
- Individual x86 flags as separate SSA values — φ-nodes apply to flags at control-flow merges.

**Memory model:**
- Byte-addressable with store-forwarding (narrow store overlapping wider load handled correctly).
- Configurable "safe-to-promote" memory ranges (e.g. obfuscation-private state vs user data).
- `Memory` value threaded to model ordering (remill pattern).

---

## 4. Module Structure (Rust Workspace)

```
kamy/
├── Cargo.toml              # workspace root
├── crates/
│   ├── kamy-core/          # IR types, Link/Symbol/Chunk, AuxData
│   ├── kamy-pe/            # PE parser/emitter, .pdata/.xdata, .reloc, imports
│   ├── kamy-disasm/        # Disassembler (wraps iced-x86), CFG recovery, function discovery
│   ├── kamy-lift/          # SSA lifter (x86 → IR), instruction semantics
│   ├── kamy-analysis/      # Symbolization, register value analysis, jump tables
│   ├── kamy-transforms/    # Transform passes (mutation, MBA, CFF, OP, diversify)
│   ├── kamy-codegen/       # Instruction selector, register allocator, assembler
│   ├── kamy-link/          # Linker: section layout, relocation resolution, PE rebuild
│   ├── kamy-seh/           # SEH/unwind: parse/rebuild RUNTIME_FUNCTION, UNWIND_INFO, C_SCOPE_TABLE
│   ├── kamy-verify/        # SMT verification, test-vector equivalence, coverage reporting
│   ├── kamy-config/        # Profile/config parsing (YAML), per-function layer selection
│   ├── kamy-observe/       # tracing subscriber + log config (terminal-first diagnostics)
│   └── kamy-cli/           # CLI binary
├── docs/
│   ├── research.md
│   ├── architecture.md
│   └── grilling.md
└── tests/
    ├── seh/                # MSVC SEH test binaries (seh0001..seh0058+)
    ├── transforms/         # Per-transform correctness tests
    └── e2e/                # End-to-end: protect binary → run → verify behavior
```

---

## 5. Protection Profile Configuration

Per-function, per-layer, composable. YAML format (matching CodeDefender's config schema).

```yaml
version: 1.0.0
module_settings:
  import_protection: false
  obscure_entry_point: false
  clear_unwind_info: false
  fake_pdb_string:
    enabled: false
    value: ''
  custom_section_name:
    enabled: false
    value: ''

profiles:
- name: light
  passes:
  - type: ObscureReferences
  - type: MutationEngine
    iterations: 1
    probability: 100
    semantics:
      add: true
      sub: true
      and: true
      xor: true
      or: true
      not: true
      neg: true
    bitwidths:
      bit8: true
      bit16: true
      bit32: true
      bit64: true
  compiler_settings:
    assembler_settings:
      shuffle_basic_blocks: true
    optimization_settings:
      constant_propagation: true
      instruction_combine: true
      dead_code_elim: true
      prune_useless_block_params: true
    lifter_settings:
      lift_calls: true
      calling_convention: WindowsAbi
      max_stack_copy_size: 512
      split_on_calls_fallback: true
  symbols:
  - !Name main
  - !Name crypto_encrypt
  - !Pattern "auth_*"
  - !Address 0x140001000

- name: heavy
  passes:
  - type: ObscureReferences
  - type: ObscureConstants
  - type: MixedBooleanArithmetic
    iterations: 2
    probability: 100
    semantics: { add: true, sub: true, and: true, xor: true, or: true, not: true, neg: true }
    bitwidths: { bit8: true, bit16: true, bit32: true, bit64: true }
  - type: LoopEncodeSemantics
    iterations: 1
    probability: 25
    semantics: { add: true, sub: true, and: true, xor: true }
    bitwidths: { bit8: true, bit16: true, bit32: true, bit64: true }
  - type: MutationEngine
    iterations: 1
    probability: 100
    semantics: { add: true, sub: true, and: true, xor: true, or: true, not: true, neg: true }
    bitwidths: { bit8: true, bit16: true, bit32: true, bit64: true }
  compiler_settings:
    assembler_settings:
      shuffle_basic_blocks: true
    optimization_settings:
      constant_propagation: true
      instruction_combine: true
      dead_code_elim: true
      prune_useless_block_params: true
    lifter_settings:
      lift_calls: true
      calling_convention: WindowsAbi
      max_stack_copy_size: 512
      split_on_calls_fallback: true
  symbols:
  - !Name decrypt_key
  - !Pattern "crypto_*"

exclude:
- pattern: "test_*"
  reason: "test functions"
```

`module_settings.custom_section_name` is optional and disabled by default. It applies
only to the Windows x86-64 PE32+ pipeline; it does not enable payload injection.
With `enabled: false`, the value is ignored: emitted code and read-only metadata
use `.kamy`, and the fresh exception table uses `.pdata`.

With `enabled: true`, `value` is an exact section-name override shared by emitted
code, read-only metadata, and the exception table. A nonempty decoy MUST contain
only ASCII bytes, MUST NOT contain NUL, and MUST be at most eight bytes. Invalid
enabled values fail profile loading with `module_settings.custom_section_name`
context; names are never silently truncated. Short names are NUL-padded in the
eight-byte PE header field.

An enabled empty value (`value: ''`) blanks those output names, the section
containing the final entry point, and any retired exception-table slot reused
for live helpers. A nonempty decoy rebrands only the obfuscator-owned output
family; unrelated resident code sections keep their names, and a recycled helper
slot is named `.text`. This policy changes names, not entry-point code bytes or
residency. Library callers select blank policy by making `Options.code_section`,
`Options.metadata_section`, and `Options.pdata_section` all empty.

Section names are cosmetic. Windows loads code and finds directories through
RVAs, section characteristics, and directory records, not these names. Rebuilding
and relocation correctness MUST NOT depend on the configured spelling.

**Selection methods:**
- By symbol name (`!Name`)
- By pattern (`!Pattern` with glob matching)
- By address (`!Address`)
- By function list file (start:end per line)
- By PDB symbol

---

## 6. Analyze Phase

### 6.1 PE Parsing
- Parse all PE headers, sections, directories
- Extract `.reloc` (base relocations) — ground truth for symbolization
- Extract `.pdata`/`.xdata` (unwind info, SEH scope tables)
- Parse imports (IAT/ILT), exports, TLS callbacks
- Optional PDB for symbol names, types, line info

### 6.2 Function Discovery (parallel, like k0mkc)
1. Seed from `.pdata` entries (every non-leaf function has one)
2. Seed from export table, PDB symbols, known entry points
3. Recursive disassembly from seeds to discover basic blocks
4. Call-target analysis: scan for CALL instructions → discover more functions
5. Gap analysis: linear sweep between known functions for missed ones

**Performance target:** 750K+ functions in <10s using rayon parallelism (k0mkc achieves this).

### 6.3 Complete Reference Model ([#18](https://github.com/mkxto/kamy/issues/18))

The shared model tracks source, target, kind, per-function incoming/outgoing references, and unresolved references. PE adapters enumerate directory fields; core reference types remain format-agnostic (D16).

| Reference class | Consumer |
|---|---|
| Direct branch / RIP-relative code or data | Recompute rel32/disp32 at final layout, inbound and outbound (#19) |
| Loader-relocated absolute VA64 | Rebase stored pointer and rebuild loader fixup (#30) |
| Known image-relative RVA32 | Rewrite the identified field; never infer all dwords are pointers |
| Recovered switch | Intra-function CFG edges consumed by table-free lowering; never patch a table |
| Unwind boundaries / entry | Regenerate exception metadata as a whole; redirect eligible entry field (#20/#27) |
| Export / TLS / load-config / debug references | Parse with PE semantics, then rewrite or regenerate (#18/#27/#33/#35) |
| Opaque / unresolved consumer | Keep the target resident; report host safe-reject |

**Host:** consume relocations, unwind, directories and optional PDB first, then conservative decoded-reference/value analysis. Unknown address materialization or ambiguous consumers block movement. Confidence is evidence, not permission to omit references. A translation map (#22) is valid only at consumers that actually consult it, never a substitute for an unknown consumer.

**Authored module:** compile Kamy's Rust module as a specialized DLL with data directories **unmerged, one directory per section**. Lift functions as code symbols and `.rdata`/`.data`/`.bss` as data symbols; import authored relocations directly into the same linker model. Reference coverage is **exact by construction**, not host inference, so host safe-reject does not gate module references. Instruction/ABI/unwind and D5 zero-spill correctness still apply. This is not a COFF-only SDK contract ([vendor specification](https://codedefender.io/blog/2025/03/27), [#32](https://github.com/mkxto/kamy/issues/32), D38).

Switch recovery remains D24's relocation evidence + per-function use-def DAG / `petgraph` VF2 + value-analysis fallback. Prove bounds and in-function targets or reject. A rejected/untouched function keeps its original table; a lowered function emits none.

---

## 7. Transform Phase

### 7.1 Pass Pipeline

Ordered, composable. All passes operate on the SSA IR. The pipeline for each function:

```
1. Lift                      — x86 → SSA IR (lift_calls + split-on-call fallback)
2. Obfuscation passes        — ordered, profile-selected:
     ObscureReferences       — hide cross-references
     ObscureConstants        — hide/encrypt constant values
     MbaPass                 — mixed boolean arithmetic (configurable semantics/bitwidths/iterations)
     MutationEngine          — instruction mutation (SSE-aware)
     LoopEncodeSemantics     — encode add/sub/and/xor as an iterative loop
     CffPass                 — control-flow flattening
     OpaquePredicatePass     — inject provably-invariant predicates
     DeadCodeInjectPass      — realistic dead-code with dataflow
3. Optimize                  — constant propagation, instruction combine, DCE
4. Compile                   — instruction selection + register allocation (linear scan)
5. Assemble                  — encode via iced-x86, shuffle basic blocks
```

Steps 1, 3, 4, 5 always run. Step 2 is profile-configured: a "light" profile might run only
ObscureReferences + MutationEngine; a "heavy" profile runs all passes with multiple iterations.

### 7.2 Pass Invariants
Every pass must:
- Preserve EFLAGS where the original instruction didn't modify them
- Preserve all registers not explicitly targeted
- Maintain valid Link/SymbolicExpression annotations for all references
- Report functions it cannot safely transform (don't silently break)
- Be independently testable (SMT verification or test-vector equivalence)

---

## 8. Rebuild Phase

### 8.1 Code Generation
- Instruction selection: IR ops → x86 instruction sequences
- Register allocation: linear-scan; D5 zero-spill is a hard constraint; if reduced-intensity/identity lowering fails, reject in place, never verbatim-relocate
- Stack-frame reconstruction from high-water mark
- Encode via iced-x86

### 8.2 Linking & PE Emission (D37)
- Place selected/lowered bodies in `.kamy`, using PIC rel32/RIP-relative code where possible; resolve links at final addresses.
- Rewrite both directions, including calls/data references from resident code. Rebase absolute `.reloc` pointers and retain required loader fixups ([#19](https://github.com/mkxto/kamy/issues/19), [#30](https://github.com/mkxto/kamy/issues/30)).
- Regenerate unwind metadata for moved host and module functions, matching generated prologues, function bounds, and supported EH scopes ([#20](https://github.com/mkxto/kamy/issues/20)). Store xdata alongside the translation table and rebuilt Import/Debug/BaseReloc directories in a shared read-only `.kamy` section; emit the fresh Exception table separately in `.pdata`. No unwind-preserving entry stub.
- Retire per-function original-VA thunks and `NoThunkSpace`. Use known address translation only where its consumer is rewritten; opaque targets stay resident ([#22](https://github.com/mkxto/kamy/issues/22)).
- Rebuild Import/Debug/BaseReloc/Exception directories without stale duplicate descriptions ([#27](https://github.com/mkxto/kamy/issues/27)). A retired Exception slot may become live RX `.text` helpers only when the retired directory wholly accounts for its contents and no active external references or other data/directories pin it. Section names alone never prove reuse is safe.
- Reclaim selective interior holes **in place** (repurpose/decoy-fill), without an `int3` thunk-flood; truncate only a provably dead contiguous code tail. Survivors retain their original RVAs and section-header ordinals. Retain the original SectionAlignment-rounded virtual coverage independently of raw tail removal: PE mapped sections MUST stay adjacent, including a fully retired code section. Raw-file repacking is not whole-image virtual compaction; pinned survivors do not slide.
- Rewrite LoadConfig to a consistent **non-enforcing default**: preserve valid security-cookie references, use non-enforcing CF check/dispatch targets, and clear stale function-table-present state or retain valid metadata. Enforcing CFG is a later opt-in, not a correctness gate here ([#33](https://github.com/mkxto/kamy/issues/33)).
- Update section headers, directories, image sizes/checksum, and optionally emit a debug/address map.

For supported plain lowered code, `kamy-seh` derives stack/nonvolatile state from the final machine CFG and emits per-state Version 2 unwind ranges. Version 1's epilogue scan can mistake a cross-fragment jump for function exit and ignore the recorded allocation. Saved-register offsets use the fixed frame base, not incrementally restored RSP. Windows `RtlVirtualUnwind` verifies Version 2 branch/empty-frame handling and full unscaled saved-XMM offsets. Dynamic frames and unprovable handler/scope state remain safe-rejects.

### 8.3 Entry Points, DLLs & Optional Modules (D38)
- EP redirection and relocating the original startup are independent. EXE startup may remain resident or move when references are resolved; a structural redirect does not imply payload injection.
- A transform-only returnable DLL entry is addressed **directly in `.kamy`**, with no `.text` stub; preserve arguments and return to the loader. Rebase moved exports' EAT RVAs and preserve DLL/header semantics ([#35](https://github.com/mkxto/kamy/issues/35)). Kernel EP remains pinned and untouched.
- Payload injection is per-build, **off by default and off for kernel entries** ([#32](https://github.com/mkxto/kamy/issues/32)). Authored module functions use the same passes and unwind regeneration as lowered host functions; module RW data does not imply a mandatory runtime.
- The [published vendor init loader](https://github.com/codedefender-io/plugins) forwards three entry arguments, status-checks callbacks, and shows a past-`end` `musttail`. In the shipped EXE, the original nonreturning startup is the last element **inside** `[begin,end)`; the past-`end` call is dead and MUST NOT be replicated as a continuation. A returning `DllMain` success (`TRUE`) MUST NOT be status-checked against zero. DLL injection instead preserves the entry arguments/return with payload-then-tail-entry sequencing, or a separately handled final callback. Preserve TLS ordering and CET.
- Optional section-name blanking/rebranding is **off by default**, separate from relocation correctness; `.kamy` is the normal code/metadata name and `.pdata` holds the fresh exception table ([#34](https://github.com/mkxto/kamy/issues/34)). The existing `module_settings.custom_section_name` toggle controls the policy described in §5. A general public SDK remains deferred.

Vendor module claims (enforcing CFG, longjmp/SAFESEH registration, unwind-safe syscalls) are not measured sample behavior or additional gates for this epic ([vendor blog](https://codedefender.io/blog/2025/03/27)).

### 8.4 CET Compatibility
- Any pass that fakes CALL/RET must emit RDSSPQ feature check + INCSSPQ reconciliation
- ENDBR64 insertion at indirect branch targets if CET-IBT is enabled
- Never emit a RET that doesn't correspond to a real CALL

---

## 9. Multithreading Strategy

Functions are parallel lift/transform/codegen units after shared reference analysis. Residency, inbound rewrites, and final layout are coordinated globally.

```
Main thread:
  Parse PE → build Module → discover functions → build complete reference model → select movable functions

Per-function (rayon work-stealing):
  For each function:
    1. Determine applicable profile
    2. Run selected SSA transform passes
    3. Emit transformed code + metadata
    4. Report coverage / errors

Main thread:
  Collect results → pin rejects/unresolved targets → layout → rewrite all affected references → rebuild directories → emit PE
```

Thread-local caches for expression simplification (VTIL model). No global locks in hot paths.

### 9.1 Observability

Errors are standardized on `anyhow` (D32): every fallible fn returns
`anyhow::Result<T>`, with `.context()` attaching a message at each boundary and
`bail!`/`ensure!`/`anyhow!` raising. No `thiserror` enums remain.
`kamy_core::RejectionReason` stays structured domain data (D22) and is never an
error.

Diagnostics use `tracing`. `kamy-observe` owns the terminal-first subscriber;
`kamy-cli` installs it via `kamy_observe::init`, and library crates only emit
events and spans. Severity is a contract: `warn!` for graceful degradation or
rejection (pass skipped, intensity reduced, function rejected, register
pressure, symbolization below threshold, fallback), `info!` for milestones with
counts, `debug!` for per-unit detail, `trace!` for per-instruction/interval
detail; `error!` is reserved for the front-end. Level and per-crate scope are
controlled by `KAMY_LOG` (EnvFilter syntax, e.g.
`KAMY_LOG=warn,kamy_link=debug,kamy_transforms=trace`) or the CLI flags
`-v`/`-vv`, `-q`, `--log`, and `--log-format <compact|tree|json>`. Diagnostics
go to stderr; stdout carries command results.

---

## 10. SaaS & CI Integration

### 10.1 API Surface
```
POST /analyze          — upload PE + optional PDB, get function list + eligibility report
POST /protect          — upload PE + profile config, get protected PE + debug map + coverage report
GET  /report/{id}      — get detailed per-function transform report
```

### 10.2 CLI
```
kamy analyze input.exe --pdb input.pdb --output report.json
kamy protect input.exe --profile profile.toml --output protected.exe --debug-map debug.json
kamy verify  input.exe protected.exe --test-vectors 1000
```

### 10.3 CI Integration
```yaml
# GitHub Actions example
- name: Protect binary
  run: kamy protect build/app.exe --profile .kamy/production.toml --output build/app.protected.exe

- name: Verify protection
  run: kamy verify build/app.exe build/app.protected.exe

- name: Run tests on protected binary
  run: ./build/app.protected.exe --self-test
```

---

## 11. Correctness Non-Negotiables

These must work before any feature is shipped:

1. **Relocation correctness** — every reference tracked as a Link, resolved correctly after relayout
2. **EFLAGS preservation** — PUSHF/POPF around any mutation that taints flags where the original didn't
3. **Register preservation** — push/pop around every scratch register use
4. **Switch handling** — recover with D24 use-def DAG + petgraph VF2 and proven bounds; lower table-free; never rewrite table entries
5. **SEH/unwind preservation** — parse, rebuild, re-point .pdata/.xdata/C_SCOPE_TABLE
6. **CET compatibility** — shadow stack reconciliation for any CALL/RET manipulation
7. **Graceful rejection** — report untransformable functions, never silently break
8. **Differential self-test** — no-transform round-trip produces functionally equivalent binary

---

## 12. Risk Register

| Risk | Impact | Mitigation |
|------|--------|------------|
| Symbolization errors corrupt binary | Fatal | Complete per-function model + conservative host safe-reject; exact authored-module metadata |
| SEH reconstruction bugs | Crash on exception | MSVC SEH test suite, 58+ tests as gate |
| MBA rules unsound for edge widths | Wrong computation | SMT bit-vector proof per rule at authoring time |
| CET shadow stack corruption | Crash on modern CPUs | RDSSPQ/INCSSPQ reconciliation, test on CET hardware |
| Register/flag clobber in mutations | Silent corruption | PUSHF/POPF + push/pop discipline, per-pass verification |
| Switch targets missed | Wrong branch target | Proven bounds + function-range checks; table-free lowering, otherwise reject in place |
| Performance overhead too high | Unusable output | Per-function profiling, tiered protection, user control |
| IR complexity explosion | Slow transforms | Copy-on-write expressions, e-graph reset, thread-local caches |
