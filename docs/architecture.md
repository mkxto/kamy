# Kamy — Architecture & Design

Binary-to-binary protection engine. 100% Rust.
Composable, per-function, per-layer protections with scriptable configuration.
Targets Windows x86-64 PE32+ only. x86/PE32 support is explicitly out of scope; no 32-bit pipeline is planned. ELF and ARM64 remain future targets.

This document separates the approved target from current contracts. D40 and the ordered [repair handoffs](handoffs/00-master.md) govern the symbol/rebuild cutover and its successors. Source interfaces below do not establish runtime acceptance; exercised results belong in [STATUS.md](STATUS.md). D37–D38 supersede D2/D29/D30's original-VA thunk/runtime assumptions.

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

**Compiler-setting target surface:**
- Lifter: `lift_calls`, `calling_convention`; stack-copy/split-on-call knobs remain unimplemented and MUST be omitted from executable profiles.
- Optimizer: `constant_propagation`, `instruction_combine`, `dead_code_elim`, `prune_useless_block_params`.
- Assembler diversification remains target work; unsupported explicit requests MUST fail. See [tooling.md](tooling.md) for accepted values, not the vendor catalog.

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

Layout-sensitive operands carry a `SymbolicExpression`, not an integer later recognized as an address. `Symbol { symbol, addend }` preserves a signed symbol-relative value; `Difference { left, right, addend }` preserves a relationship between two identified symbols. The relocation field separately specifies absolute, image-relative or PC-relative encoding. Ordinary integer constants remain ordinary constants, including values equal to an address.

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
│   ├── kamy-sdk/           # no_std SDK boundary; std module/runtime support is a later target
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

Per-function, per-layer, composable. YAML format with a CodeDefender-shaped configuration surface. This example uses the implemented subset. The exact supported settings and strict errors are documented in [tooling.md](tooling.md); unsupported enabled requests MUST fail rather than be ignored.

```yaml
version: 1.0.0
module_settings:
  custom_section_name:
    enabled: false
    value: ''
  injection:
    enabled: false
    mode: init-table
    plugins: []

profiles:
- name: arithmetic
  passes:
  - type: MixedBooleanArithmetic
    iterations: 2
    probability: 100
    semantics: { add: true, sub: true, xor: true }
    bitwidths: { bit8: true, bit16: true, bit32: true, bit64: true }
  symbols:
  - !Name crypto_encrypt
  - !Pattern 'auth_*'
  - !Address 0x140001000

exclude:
- pattern: 'test_*'
  reason: 'test functions'
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

**Selection:** `!Name`, `!Pattern` (`*`/`?`), reusable `!Group`, host-only
`!Address` (RVA or VA), and host `!TopXref` operate on metadata entries.
Authored names use `plugin::symbol`; module-local coordinates are not host
addresses. Empty `symbols:` selects all entries. Exclusions win globally;
the first matching profile owns each remaining symbol. Later profiles do not
append passes. Numeric ambiguity/range errors and CLI RVA-selector/profile
conflicts are explicit; see [tooling.md](tooling.md). Profile-plus-identity
retains injection/naming/nonsemantic policy and suppresses semantic passes.

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

**Authored module:** compile Kamy's Rust module as a specialized DLL with dedicated data-directory ownership. Compiler-authored code/data symbols and relocation expressions enter the same shared linker model and final rebuild as host inputs. Their provenance is exact, not host inference; instruction, explicit call ABI, frame and unwind correctness still apply (D38/D40). Rust builds may require version-matched LLVM tooling to produce ABI metadata validated against the exact emitted code. Native COFF is an intermediate, not a public C/C++ SDK contract.

Switch recovery remains D24's relocation evidence + per-function use-def DAG / `petgraph` VF2 + value-analysis fallback. Prove bounds and in-function targets or reject. A rejected/untouched function keeps its original table; a lowered function emits none.

### 6.4 Shared symbol/reference contract (handoff 1)

The shared definitions live in `kamy-core`, not in a module-only address model:

- `SymbolId::Host { rva }` identifies a host source coordinate.
- `SymbolId::Authored { module, symbol }` identifies a plugin instance and its
  exact compiler symbol identity. Display names and module-local decode RVAs are
  not identities. Two artifacts may use the same source RVA without collision;
  loading one artifact twice gives distinct instance-qualified identities.
  String-bearing identity fields use shared immutable `Arc<str>` storage.
- `Generated { name }` and `HostImageBase` distinguish helpers and the true host
  header/base anchor. Existing host IAT slots use `Host { rva }` storage identity
  with `SymbolKind::Import`, not an unused logical-import namespace. Handoff 3
  owns new module imports and their real loader relationships.
- `Reference { source, offset, expression, field, origin }` identifies a field
  relative to its containing source symbol. `ReferenceOrigin` records
  `HostAnalysis`, `HostMetadata`, `Authored` or `Generated` provenance.
- `SymbolicExpression::{Symbol, Difference}` retains signed addends and symbol
  differences. `LinkField::{Absolute64, ImageRelative32, Relative32 { bias }}`
  owns checked encoding: absolute VA64; value minus host image base as RVA32;
  or value minus `(field_va + 4 + bias)` as signed rel32. Negative compiler
  addends and trailing-immediate bias MUST NOT be flattened into a guessed RVA.
  `LinkField::encode_into` writes only an exact-width caller-provided slice and
  checks conversions; it does not allocate a relocation buffer.
- `HostReference { source, target, kind }` remains host-analysis evidence with
  local RVAs. It is not a second authoritative module/link binding model, and
  representable references alone do not establish host completeness.

`OperandReference { instruction, operand, reference }` attaches exact provenance
to an operand at the unmodified local decode coordinate. `lift_function` takes
these annotations as its final slice argument. Host callers may pass an empty
slice and symbolize decoded direct/RIP references from host coordinates;
authored callers MUST pass their exact metadata. There is no MOVABS-to-LEA byte
normalization or reserved numeric namespace.

`IrOp::Address(Reference)`, symbolic `IrOp::Call` targets and symbolic tail
targets carry provenance through SSA, copies, phis and optimization. Address
leaves are opaque, not integer constants. `select_instructions` returns
`SelectedInstructions { instructions, references }`; each `InstructionReference`
nominates an instruction index, operand and reference. `bind_references` binds
those operands using a final `SymbolId` resolver before relocating the selected
instructions. Encoder-local branch labels remain separate. They MUST NOT be
interpreted as link symbols or used to rediscover lost provenance.

Code operand annotations contain semantic values: relative fields include the
decoded next-IP correction, and image-relative operands use a `Difference`
against `HostImageBase` with semantic `Absolute64` field. Original data-field
writes retain raw signed addends/bias. The binder MUST NOT apply the original
input field semantics a second time.
`NativeInst { bytes, references, reads, writes }` retains exact
`Vec<OperandReference>` provenance for supported RIP64 memory operands in opaque
`NativeInline` operations. Selection emits normal `InstructionReference`
fixups, consumed by the same final binder; raw bytes alone are not a relocation
contract. Authored annotations MUST match the original source field/operand and
retain raw compiler addends/bias. `REL32_0` may encode a negative raw addend for
trailing bytes; field bias need not equal the architectural instruction tail.
The semantic operand target already includes next-IP correction, which the
binder MUST NOT apply again. Existing EIP-relative/flag/semantic checks remain
independent eligibility constraints.

`kamy_transforms::resolve_image_base_uses(func, classify) -> bool` runs after
SSA and before optimization. After shared DCE removes dead flag producers, it
derives proven base-plus-constant relationships through copies/phis/Add/Sub and
asks the host adapter to classify object/interior targets or true header/base
anchors. Identified objects become opaque address leaves before placement, so
their final locations can change. A true return constrains movement for
unresolved/escaping raw-base consumers, including live ambiguous arithmetic
flags. Equal-valued integer constants do not acquire pointer provenance.

### 6.5 Authored-call contract

`kamy_core::ir::FnSignature { args, returns, clobbers, noreturn }` is the shared
call contract. Each argument/return is an `AbiValue { location, class, bits,
passing }`. `AbiLocation` is a physical register or a stack offset in bytes from
callee-entry RSP, with the return address at offset zero. `AbiClass` distinguishes
integer, float, vector and pointer. `AbiPassing` is `Direct`,
`Indirect { size, align }`, or `Sret { size, align }`; sret describes the hidden
result-pointer argument. A decomposed aggregate uses separate machine-ordered
pieces. Multiple returns are separate values, not aliases of one RAX result.
`IrOp::Call { target, clobbers }` and `CallIndirect { clobbers }` carry actual
call effects. Each `CallResult { register }` is a separate no-code SSA result
definition pinned to its register/class, without allocating a call-token value.
The call remains a side-effect root for DCE. Consumers MUST preserve result
ordering and explicit clobbers through optimization/allocation; the symbolic
fixup belongs to the direct target. Proven `noreturn` calls end with
`IrTerminator::NoReturn`, distinct from unsupported `Unreachable`; decoding
stops there and selection emits no synthetic return/epilogue after the call.

`CallingConvLookup::lookup(target_va)` serves source decoding;
`lookup_symbol(&SymbolId)` serves exact authored calls. Unknown authored calls
MUST fail closed, not use the host four-GPR/RAX default. The public callback's
Win64 `extern "system"` ABI does not establish the ABI of internal Rust calls.
Host lookup retains callee inference, named import slots and import-thunk
precedence, using the existing Win32metadata/CRT signatures before conservative
unknown-host behavior. No mangled-name ABI inference or Rust ABI stability is
assumed. Metadata representation does not imply every represented instruction,
frame or aggregate shape is currently lowerable.
Authored callee preservation also matters: compiler-preserved Win64-volatile
GPR/XMM values remain pinned live-outs at return/tail boundaries. This preserves
decoded restores and prevents scratch allocation from overwriting untouched
values; the existing nonvolatile save/unwind machinery remains shared. Current
limitations include R11 flag replay conflicting with pinned R11, CL-based
shift/rotate lowering for exact contracts preserving RCX, and unknown stack
return locations. Immediate shifts do not require that CL scratch path.
Physical constraints attach to real boundaries: function-entry live-ins, local
call/native operand copies and return copies. Logical GPR/XMM moves detach the
value from a source physical pin rather than extending that pin through every
alias and later call. Multiple consumers MUST NOT turn a return constant, phi
or copied call result into an unrelated function-wide register constraint.
This repairs boundary representation; it is not spilling, concrete-frame
reconstruction or the pressure guarantee assigned to handoff 2.

Implicit arithmetic uses explicit machine boundaries. `UDiv`/`SDiv` take
`[high, low, divisor]`, with fixed RDX/RAX dividend inputs and quotient in RAX.
`URem`/`SRem` take the quotient as a dependency and project RDX from that same
division; a remainder-only consumer MUST NOT emit a second division.
`UMulHi`/`SMulHi` take `[lhs, rhs]`, with lhs in RAX and the high result in RDX;
the immediately dependent unary `Mul [high_product]` projects the low RAX result
from the same hardware multiplication. Binary `Mul` remains an independent
operation. Allocation retains the producer's RAX result until its low projection,
and both outputs are snapshotted. Multiplication clobbers RAX/RDX. Architectural
inputs and sources are snapshotted before boundary pins; this path adds neither
R10/R11 scratch nor spill/frame storage.
Supported widths are I8/I16/I32/I64, with byte division using AX and AL/AH.
Signed IMUL overflow compares the high result with the low result's sign
extension. Divisions remain DCE roots even with dead results, preserving
divide-by-zero and quotient-overflow faults. Malformed or I128 forms fail
preflight rather than entering a partial lowering.

---

## 7. Transform Phase

### 7.1 Pass Pipeline

Ordered, composable. All passes operate on the SSA IR. The pipeline for each function:

```
1. Lift                      — x86 → SSA IR with modeled call contracts
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

Steps 1, 3, 4 and 5 run for accepted functions. Step 2 is profile-configured.
The catalog above is the target, not the implemented pass inventory. Supported
MBA entries MUST run in declared order; first-MBA-only execution is not a valid
interpretation of a profile. Unsupported enabled passes/settings MUST fail with
profile/setting context. Semantic identity suppresses semantic passes, not module
injection, naming or other supported nonsemantic policy.

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
- Register allocation: D40 adopts memory-backed intermediates and bounded scratch sets; handoff 2 owns that backend cutover. Until then, report pressure-driven reductions and identity lowering honestly; never verbatim-relocate failures.
- Concrete original-frame reconstruction and memory-home integration are handoff-2 work, not implied by current generated save frames or plain unwind support.
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

The single public entry is `kamy_link::protect(pe, host, functions, opts, cc,
transform, injection) -> Result<(Vec<u8>, Report)>`. Host-only callers pass
`module::Injection` with an empty plugin slice. The transform callback is
`FnMut(&SymbolId, &mut IrFunction, f32) -> Result<TransformOutcome>`;
`TransformOutcome.transformed` reports actual semantic changes, and callback
errors propagate. The old `protect_with_transforms`/`protect_with_modules`
entries and intermediate host-output reparse are removed.

Internally, `plan_image` prepares original host evidence and
`module::Plan::prepare` validates/lowers authored inputs before host placement.
Module `place`/emission contributes to the same original-host `PeEdits`;
`protect` performs the only final `PeFile::rebuild`. Host/module slots grow
monotonically with checked extents and explicit 4,096-iteration bounds, failing
on nonconvergence rather than overwriting a neighbor. Final binding uses the
same source identities at every placement iteration. Original module decode
RVAs and image bases are not shifted into a synthetic host range.

`Options.selected_symbols: Option<BTreeSet<SymbolId>>` complements the existing
host-only `FunctionSelector`. Unselected host bodies remain resident. Every
authored body still MUST lower/link; unselected authored bodies skip semantic
callbacks and report `selected=false`, `lowered=true`, `intensity=0`.
`module::planned_functions(&[Plugin])` returns metadata-derived
`PlannedFunction { plugin, name, symbol }`, not fake source coordinates or CFGs.

The `Report` exposes `moved`, `(symbol, reason)` `rejected`, `ssa_lowered`,
`ssa_lowered_symbols`, `address_map: BTreeMap<SymbolId, Rva>`, `functions`,
`placements` and `directories`. `FunctionReport` separates selection,
eligibility, lowering, actual transformation and successful intensity. The
temporary pressure ladder is `1.0 → 0.5 → 0.25 → 0.0`; report only the successful
attempt, with identity/no-transform intensity zero. Only `RegisterPressure`
permits this retry; other structured allocation/domain failures propagate with
their actual reason rather than being relabeled pressure. The ladder is not the
D40 target.

`Placement { symbol, source_rva, rva, size, ownership }` records retained,
resident, generated or retired ownership. A source RVA is optional, not a global
module identifier. `DirectoryReport { index, rva, file_offset, size, contributions }` uses
`Vec<Placement>` contributions: Exception records identify actual runtime
begin/length ranges; BaseReloc contributions identify actual field RVA/width.
Empty index-3/index-5 reports have zero size and no contributions. Generated
`directory-3`/`directory-5` placements identify the single active table ranges;
replaced original table storage is retired. Retained old bytes alone do not
constitute an active duplicate table.
`file_offset` is optional: ordinary directories use RVAs, while certificate
directory index 4 records the actual final file offset and RVA zero. Certificate
storage has no address-map row; it is not an image-address symbol.
`PeFile::output_data_directory` reads the final emitted directory record after
the sole rebuild, without reparsing an intermediate image. Certificate
contributions are retained file storage, not mapped RVA placements. Preserving
certificate bytes does not preserve Authenticode validity after modification.

Generated entry-loader/startup/init-table inputs and indirect-translation/CFG
helpers remain part of this plan. Host and authored indirect consumers share
the translation helpers and original-host translation table. Handoff 3 owns
the compiled-loader replacement. Module data preserves permissions and BSS:
`NewSection.virtual_size` is independent of initialized `data.len()`, MUST be
at least that length, and permits a virtual zero-fill tail. Data relocations and
linker-filled bounds MUST fit existing initialized bytes; link planning MUST NOT
extend raw storage into BSS to write them. Debug/certificate/overlay consumers
retain file-coordinate semantics through the existing raw rebuild machinery.
Generated placement names are `entry-loader`, `startup`, `init-table`,
`translation-{register:?}`, `cfg-check` and `directory-{index}` when present.
Consumers MUST use symbol/ownership/range data, not section spelling, to locate
these artifacts. Absent helpers do not require empty generated sections.

### 8.3 Entry Points, DLLs & Optional Modules (D38)
- EP redirection and relocating the original startup are independent. EXE startup may remain resident or move when references are resolved; a structural redirect does not imply payload injection.
- A transform-only returnable DLL entry is addressed **directly in `.kamy`**, with no `.text` stub; preserve arguments and return to the loader. Rebase moved exports' EAT RVAs and preserve DLL/header semantics ([#35](https://github.com/mkxto/kamy/issues/35)). Kernel EP remains pinned and untouched.
- Payload injection is per-build, **off by default and off for kernel entries** ([#32](https://github.com/mkxto/kamy/issues/32)). Authored module functions use the same passes and unwind regeneration as lowered host functions; module RW data does not imply a mandatory runtime.
- The [published vendor init loader](https://github.com/codedefender-io/plugins) forwards three entry arguments, status-checks callbacks, and shows a past-`end` `musttail`. In the shipped EXE, the original nonreturning startup is the last element **inside** `[begin,end)`; the past-`end` call is dead and MUST NOT be replicated as a continuation. A returning `DllMain` success (`TRUE`) MUST NOT be status-checked against zero. DLL injection instead preserves the entry arguments/return with payload-then-tail-entry sequencing, or a separately handled final callback. Preserve TLS ordering and CET.
- Optional section-name blanking/rebranding is **off by default**, separate from relocation correctness; `.kamy` is the normal code/metadata name and `.pdata` holds the fresh exception table ([#34](https://github.com/mkxto/kamy/issues/34)). The existing `module_settings.custom_section_name` toggle controls the policy described in §5. D39 supplies the configurable Rust-only SDK/plugin interface; no C/C++ plugin surface.

Vendor module claims (enforcing CFG, longjmp/SAFESEH registration, unwind-safe syscalls) are not measured sample behavior or additional gates for this epic ([vendor blog](https://codedefender.io/blog/2025/03/27)).

### 8.4 Rust SDK & Plugin Configuration (D39)

`kamy-sdk` is a dependency-free `no_std` Rust crate. The current freestanding
module workflow is a limitation, not a no_std-only product requirement: D40
assigns Rust `std` with `panic=abort` and its runtime prerequisites to handoff 3.
`plugin!(initialize)` exports the default callback and owns the module's aborting
panic handler plus the Windows x64 MSVC `_fltused` 32-bit data marker (`0x9875`).
It MUST NOT coexist with a second runtime defining those symbols; this narrow
floating-point prerequisite is not std/CRT support. `declare_init_table!()`
optionally declares linker-filled `SYMBOL_init_table_start`/
`SYMBOL_init_table_end` cells in distinct initialized native `.data$...`
contributions, despite their initial null values. The provenance consumer rejects
bound cells originating in COFF BSS with rebuild guidance; rebuild old plugins
with the current SDK/producer rather than materializing their BSS tails.
The callback uses
`unsafe extern "system" fn(*mut c_void, *mut c_void, *mut c_void) -> i32`.
These are entry registers, not main arguments. Zero continues; nonzero fast-fails.

`kamy plugin build --manifest-path <Cargo.toml> -o <plugin.dll>` compiles a Rust
`staticlib` Cargo target for `x86_64-pc-windows-msvc` with fat LTO. The producer
API is `kamy_pe::module::build_from_llvm_ir(ir, output, entry, linker, llc,
compiler_version)`. It consumes post-LTO LLVM IR and uses version-matched `llc`
for a full native object emission while capturing machine-state metadata from
that same invocation. It does not resume serialized MIR. The LLVM 22.1.2-pinned
parser associates typed IR, native argument/return locations and compiler
symbols; compiler-name guessing and a generic Win64 default are not authored
ABI evidence. Native COFF symbols/relocations and linked section contributions
are validated against the specialized DLL. COFF remains a private intermediate,
not a public plugin input or an alternative C/C++ SDK surface.

The `KAMYMOD` embedded artifact schema is **version 2**, containing compiler ABI
metadata with native symbol/reference provenance. Older versions MUST fail with
rebuild guidance. Rebuild first-party and external plugins through the current
producer; no compatibility branch preserves the old numeric binding model.
`AuthoredModule::parse(bytes, identity)` takes the instance identity explicitly;
`CodeSymbol` exposes `symbol`, `signature`, `name`, `start`, `end`, and
`DataSymbol` exposes `symbol`, `name`, `start`, `size`. Decode coordinates remain
local to the input. `AuthoredModule.references` is the shared `Vec<Reference>`.
`AuthoredModule.symbols` preserves the complete original binding table;
`bindings: BTreeMap<SymbolId, SymbolicExpression>` maps noncanonical compiler
aliases to containing storage/function identities plus offsets. Native object
section membership establishes those bindings, including one-past aliases;
canonical code/nonexecuting storage roots have no binding. Resolve aliases
before original reference expressions, not by searching final numeric ranges.
Compiler identities use `coff:{object}:symbol:{symbol_table_index}:{native_name}`;
storage identities use `coff:{object}:section:{section_index}:piece:{offset}`.
Executable contributions contain one compiler-authored function each, preventing
a section-root addend from silently naming a separately moved neighbor.

`kamy_link::module::AuthoredSource::new(&Plugin)` is the shared source adapter
for module planning and triage. `module()` exposes its unchanged decode view;
`function_at(local_rva, Option<&Module>)` returns `AuthoredFunction { symbol,
function, references }` from exact compiler boundaries. The source implements
`CallingConvLookup` using authored contracts. With no host, host-base references
remain symbolic; with a host, the same operand preparation and host-object
classification used by the plan applies. Diagnostics MUST NOT recover a second
function/provenance model from the DLL's entry-point discovery seeds.

Consumer input is the self-contained DLL with dedicated Exception/BaseReloc
sections, not a DLL loaded into the protection process or a sidecar object.
Current module directories other than Exception/BaseReloc, language-handler
unwind and unsupported operand/SSA/frame forms fail contextually. Host imports
and TLS remain host inputs; ordinary module imports, module TLS/export runtime
semantics and std support belong to handoff 3. Exact provenance does not waive
ABI, instruction, frame or unwind limits.

Authored references retain a symbol base and signed compiler addend. An x64
`REL32` field can encode a negative addend for bytes following its displacement;
its encoded expression is not necessarily a valid standalone RVA. Rebase the
symbol before applying the addend, then let decoding recover the architectural
RIP target. `__ImageBase` binds to the host base, distinct from module-local data.

`module_settings.injection` is disabled by default. Enabling it requires an
ordered `plugins: [{name: ..., path: ...}]` list. Paths resolve relative to the
profile, not the current directory. Names MUST be unique, nonempty and contain
no `::`; profiles select module functions as `plugin::symbol`. `mode` accepts
`inline` or `init-table`. DLL entry results are propagated without treating
successful `TRUE` as a callback failure; kernel injection is prohibited.
The build command never loads the plugin into the protection process.


### 8.5 CET Compatibility
- Any pass that fakes CALL/RET must emit RDSSPQ feature check + INCSSPQ reconciliation
- ENDBR64 insertion at indirect branch targets if CET-IBT is enabled
- Never emit a RET that doesn't correspond to a real CALL

### 8.6 Contracts consumed by the next handoffs

Handoff 2 MUST reuse `SymbolId`, `Reference`, operand annotations,
`FnSignature`/`AbiValue`, symbolic selection/binding and the single link plan.
It owns the concrete frame, memory homes, bounded scratch sets and explicit
flag state. It MUST preserve exact authored call locations and actual-body
unwind, then remove pressure-only rejects/intensity retries when their causes
are repaired. The intact combined bounds-check/counter callback remains an
acceptance witness; splitting it is not frame recovery.

Handoff 3 MUST build on those same contracts and the versioned specialized DLL
producer/consumer. It owns replacing generated startup with compiled Rust
module code, ordinary imports, Rust `std` with `panic=abort`, required runtime/TLS
initialization and teardown, and process-attach-only DLL initialization. The
generated startup/helper path remains an intentional handoff-1 input, not proof
of a compiled loader or an arbitrary std-capable SDK. Current DLL callback
sequencing MUST NOT be described as the final notification lifecycle.

Handoff 4 MUST extend the same final placement, ownership and directory graph,
not parse an intermediate protected image or create a second compactor. It owns
moving completeness-proven survivors and data, rewriting affected structures,
and explicit failure when global layout cannot be justified. Selective
reclamation, dead-tail truncation and raw repacking are not whole-image virtual
compaction. Retained stale bytes are distinct from an active stale directory;
section count/name alone proves neither correctness nor vendor parity.

Each successor consumes the committed portable fixture set and the preceding
milestone's actual execution/coverage evidence. Measured vendor sample behavior,
vendor feature claims and inference remain distinct; this repair campaign does
not convert unobserved CFG/longjmp/SAFESEH extras into implemented guarantees.

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

The supported command surface and executable examples live in
[tooling.md](tooling.md). Profiles use YAML. A public service API, PDB output
and the complete transform catalog remain targets, not CLI implementation claims.

### 10.3 CI Integration
```yaml
# GitHub Actions example
- name: Protect binary
  run: kamy protect build/app.exe --profile .kamy/production.yml --output build/app.protected.exe

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
