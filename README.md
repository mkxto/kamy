# Kamy

Binary-to-binary protection engine written in Rust.

Composable mutation, MBA, control-flow protection, constant hiding, and binary diversification — applied per-function with scriptable profiles. No source code changes required.

## Architecture

```
Input PE ──▶ Analyze ──▶ Lift ──▶ Transform ──▶ Rebuild ──▶ Protected PE
                │                     │                         │
             .pdata              Composable              .pdata rebuilt
             .reloc              pass pipeline           .reloc rebuilt
             PDB                 per-function             debug map
             imports             profiles
```

**Single SSA IR engine:** every transformed function goes through lift → SSA IR → obfuscation passes → optimize → compile → link. Protection depth is controlled by pass selection and iteration count — light profiles run fewer passes, heavy profiles run more. Functions not selected by any profile are untouched.

See [docs/architecture.md](docs/architecture.md) for full design.

## Crate Structure

```
kamy/
├── crates/
│   ├── kamy-core/           IR types, Link, Symbol, Chunk, AuxData
│   ├── kamy-pe/             PE parser/emitter, .pdata, .reloc, imports
│   ├── kamy-disasm/         Disassembler (iced-x86), CFG, function discovery
│   ├── kamy-lift/           x86 → SSA IR lifter
│   ├── kamy-analysis/       Symbolization, register value analysis, jump tables
│   ├── kamy-transforms/     Mutation, MBA, CFF, opaque predicates, diversify
│   ├── kamy-codegen/        Instruction selector, register allocator, assembler
│   ├── kamy-link/           Section layout, relocation resolve, PE rebuild
│   ├── kamy-seh/            SEH/unwind: RUNTIME_FUNCTION, UNWIND_INFO, C_SCOPE_TABLE
│   ├── kamy-verify/         SMT verification, test-vector equivalence
│   ├── kamy-config/        YAML profile parsing, per-function config
│   └── kamy-cli/            CLI binary
├── docs/
│   ├── research.md          Prior art, techniques, academic references
│   └── architecture.md      System design, IR, pipeline, configuration
└── tests/
    ├── seh/                 MSVC SEH test binaries
    ├── transforms/          Per-transform correctness
    └── e2e/                 Protect → run → verify
```

## Configuration

```yaml
# kamy.yml — protection profile
version: 1.0.0
module_settings:
  import_protection: false
  obscure_entry_point: false

profiles:
- name: default
  passes:
  - type: ObscureReferences
  - type: MixedBooleanArithmetic
    iterations: 1
    probability: 100
    semantics: { add: true, sub: true, xor: true, or: true, not: true, neg: true }
    bitwidths: { bit8: true, bit16: true, bit32: true, bit64: true }
  - type: MutationEngine
    iterations: 1
    probability: 100
  symbols:
  - !Pattern "crypto_*"
  - !Name main
```

## CLI

```sh
# Analyze: discover functions, report eligibility
kamy analyze input.exe --pdb input.pdb -o report.json

# Protect: apply transforms per profile
kamy protect input.exe --profile kamy.yml -o protected.exe --debug-map debug.json

# Verify: test-vector equivalence check
kamy verify input.exe protected.exe --vectors 1000
```

## Roadmap

### Phase 1 — Foundation (current)
- [x] Research & documentation
- [x] Workspace scaffold, CI setup
- [x] PE parser (headers, sections, .reloc, .pdata, imports, exports) — emit deferred to Phase 2 linker
- [x] Disassembler integration (iced-x86)
- [x] Function discovery (from .pdata, exports, call targets)
- [x] Container IR (Module, Section, Symbol, Relocation, CFG) — Chunk/Link/SymbolicExpression land with Phase 2 symbolization

### Phase 2 — SSA IR Engine
- [x] x86 → SSA IR lifter (core GPR + basic SSE data movement)
- [x] Proper SSA construction (φ-nodes, RPO cross-block register threading)
- [ ] Calling convention database (Win32metadata, PDB)
- [ ] Instruction selector + linear-scan register allocator
- [ ] Codegen via iced-x86
- [ ] Symbolization (metadata-first pipeline)
- [x] Linker: thunk placement + new section layout + PE rebuild (relocation path via iced-x86 BlockEncoder)
- [x] Differential self-test (no-transform round-trip) — verified on a real exe; conservative function selection (D22 rejections) for indirect-branch/SEH/reloc cases

The transform-capable SSA codegen now lowers correctly-threaded IR: with the
callee-saved pool enabled it reaches 95/169 functions regalloc-ready on the test
binary (0 before the threading fix). Shipping SSA-lowered functions is gated on
callee-saved activation (push/pop + UNWIND_INFO, Phase 4); until then the
no-transform round-trip and `protect` ship via the relocation codegen path.
Remaining isel gaps: 4 XMM5 memory-operand encode failures, zero-spill pressure.

### Phase 3 — Obfuscation Passes
- [ ] ObscureReferences
- [ ] ObscureConstants
- [ ] MBA (configurable semantics/bitwidths/iterations)
- [ ] MutationEngine
- [ ] LoopEncodeSemantics
- [ ] Per-function config profiles
- [ ] Jump table recovery & retargeting

### Phase 4 — SEH & CET
- [ ] Callee-saved activation (regalloc pool + isel push/pop + UNWIND_INFO) — gates shipping SSA-lowered functions and visible MBA
- [ ] .pdata/.xdata parser & rebuilder
- [ ] UNWIND_INFO reconstruction
- [ ] C_SCOPE_TABLE re-pointing
- [ ] CET shadow stack reconciliation (RDSSPQ/INCSSPQ)
- [ ] MSVC SEH test suite (58+ tests)

### Phase 5 — Advanced Passes
- [ ] Control-flow flattening
- [ ] Opaque predicates (number-theoretic invariants)
- [ ] Advanced MBA (polynomial, per-instance keyed)
- [ ] Dead-code injection with dataflow
- [ ] Known-bits abstract domain
- [ ] Expression simplifier (cost-gated)

### Phase 6 — Production
- [ ] Coverage reporting & graceful degradation
- [ ] API server (analyze, protect, report endpoints)
- [ ] CI integration (GitHub Actions, Azure DevOps)
- [ ] ELF (x86-64) support
- [ ] ARM64 support

## Key Dependencies

| Crate | Purpose |
|-------|---------|
| `iced-x86` | x86/x64 decode, encode, assemble |
| `pdb` (fork) | PDB read + write (forked to add write support) |
| `rayon` | Parallel per-function processing |
| `egg` | E-graph equality saturation (MBA, verification) |
| `serde` + `serde_yaml` | Configuration |

PE parsing and emission is fully custom (`kamy-pe`). No dependency on `object` or `goblin`.

## Research

See [docs/research.md](docs/research.md) for the full research report covering:
- Prior art (CodeDefender, BLARE2, PERSES, Theodosius, VTIL, k0mkc)
- Techniques catalog (mutation, MBA, CFF, opaque predicates, constant hiding)
- Windows x64 SEH/unwind engineering
- CET shadow stack compatibility
- Symbolization strategies and reliability
- Adversary model (MBA attacks, devirtualization footholds)
- Verification pipeline
- Academic references (30+ papers)

## License

Proprietary. Internal use only.
