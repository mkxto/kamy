# Kamy — Architecture & Design

Binary-to-binary protection engine. 100% Rust.
Composable, per-function, per-layer protections with scriptable configuration.
Targets Windows PE (x86-64) first; ELF and ARM64 planned.

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
- `LoopEncodeSemantics` — loop-body encoding

**Compiler settings** (always present, not opt-in):
- Lifter: `lift_calls`, `calling_convention`, `max_stack_copy_size`, `split_on_calls_fallback`
- Optimizer: `constant_propagation`, `instruction_combine`, `dead_code_elim`, `prune_useless_block_params`
- Assembler: `shuffle_basic_blocks`, `instruction_prefix`, `random_prefix_chance`

**Properties:**
- Per-function selection via symbol names, patterns, addresses, PDB symbols.
- Per-function graceful rejection with reasons (`BadIndirectBranch`, `NoThunkSpace`).
- Functions not selected by any profile are untouched (zero cost).
- Embarrassingly parallel (per-function) via rayon work-stealing.
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

**Key invariant:** absolute addresses never stored. Every cross-reference is a `Link` object pointing to a target `Chunk`. Moving code = free; layout is computed at emit time. (Egalito model)

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
    semantics: { add: true, sub: true, and: true, xor: true, or: true, not: true, neg: true }
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

### 6.3 Symbolization
Metadata-first pipeline:
1. `.reloc` entries → mark as known symbolic references
2. `.pdata`/`.xdata` pointers → known
3. Import/export table references → known
4. PDB info → known
5. Infer residual: jump tables, computed addresses, switch dispatch
6. Per-reference confidence score; below threshold → mark as uncertain (handle conservatively)

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
     LoopEncodeSemantics     — loop-body encoding
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
- Register allocation: linear-scan; register pressure avoidance as first-class goal
- Stack-frame reconstruction from high-water mark
- Encode via iced-x86

### 8.2 Linking & PE Emission
- Layout new code section (`.kamy`)
- Resolve all Links to final addresses
- Emit thunks at original function sites (jmp to transformed code)
- Scrub original function bodies (int3 fill)
- Rebuild `.reloc` with new base relocations
- Rebuild `.pdata`/`.xdata` with updated RUNTIME_FUNCTION entries, UNWIND_INFO, C_SCOPE_TABLE
- Update PE headers (section table, data directories, checksum)
- Optional debug map output for PDB reconstruction

### 8.3 CET Compatibility
- Any pass that fakes CALL/RET must emit RDSSPQ feature check + INCSSPQ reconciliation
- ENDBR64 insertion at indirect branch targets if CET-IBT is enabled
- Never emit a RET that doesn't correspond to a real CALL

---

## 9. Multithreading Strategy

Functions are independent processing units — embarrassingly parallel.

```
Main thread:
  Parse PE → build Module → discover functions → symbolize

Per-function (rayon work-stealing):
  For each function:
    1. Determine applicable profile
    2. Run transform passes (Tier 1 or Tier 2)
    3. Emit transformed code + metadata
    4. Report coverage / errors

Main thread:
  Collect results → layout sections → link → emit PE
```

Thread-local caches for expression simplification (VTIL model). No global locks in hot paths.

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
4. **Jump table handling** — recover, retarget, validate
5. **SEH/unwind preservation** — parse, rebuild, re-point .pdata/.xdata/C_SCOPE_TABLE
6. **CET compatibility** — shadow stack reconciliation for any CALL/RET manipulation
7. **Graceful rejection** — report untransformable functions, never silently break
8. **Differential self-test** — no-transform round-trip produces functionally equivalent binary

---

## 12. Risk Register

| Risk | Impact | Mitigation |
|------|--------|------------|
| Symbolization errors corrupt binary | Fatal | Metadata-first + confidence thresholds + graceful degradation |
| SEH reconstruction bugs | Crash on exception | MSVC SEH test suite, 58+ tests as gate |
| MBA rules unsound for edge widths | Wrong computation | SMT bit-vector proof per rule at authoring time |
| CET shadow stack corruption | Crash on modern CPUs | RDSSPQ/INCSSPQ reconciliation, test on CET hardware |
| Register/flag clobber in mutations | Silent corruption | PUSHF/POPF + push/pop discipline, per-pass verification |
| Jump table entries missed | Wrong branch target | Bounds-check recovery + explicit entry retargeting |
| Performance overhead too high | Unusable output | Per-function profiling, tiered protection, user control |
| IR complexity explosion | Slow transforms | Copy-on-write expressions, e-graph reset, thread-local caches |
