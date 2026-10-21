# Prompt 1 — Unified symbols, authoritative references and one rebuild

Implement this assignment in the Kamy checkout. Read
`docs/handoffs/00-master.md` first; its confirmed decisions, preservation list,
no-bandaid rules and verification/commit contract are part of this prompt.
Do not implement the entire campaign in this assignment.

## Goal

Replace the architectural shortcut that protects/rebuilds the host and then
re-parses/appends modules in a second rebuild. Establish one authoritative
symbol/reference model and one final layout/emission path for host functions,
authored module functions, module data, generated helpers and PE directories.

This is a correctness/model milestone, not a request for stronger MBA, a new
spilling backend or whole-image compaction yet. It MUST leave a green working
selective pipeline for the next prompts to extend.

## Ground the work before editing

Read current source and use language-server references before exported-type
changes. Main starting points, not an exclusive file list:

- `crates/kamy-core/src/references.rs`, `src/symbol.rs`, `src/addr.rs`, `src/ir`.
- `crates/kamy-pe/src/module.rs`, `src/module/{coff,producer,tests}.rs`.
- `crates/kamy-link/src/{lib,module,layout,rewrite,translation}.rs`.
- `crates/kamy-codegen/src/{lib,references,isel}.rs`.
- `crates/kamy-lift/src/lib.rs` and its operand/SSA machinery.
- PE reference enumeration, directory rebuild and mutable-image APIs.
- `crates/kamy-cli/src/commands/{protect,plugin}.rs`, `src/target.rs`, config,
  triage/corpus callers and documented maps/flags.

At the starting anchor, `protect_with_modules` calls
`protect_with_transforms`, parses the returned PE, then emits more sections and
another Exception/BaseReloc set. The module frontend also creates synthetic
RVA namespaces, stores address bindings as numeric maps, and normalizes an
exact `mov r64,imm64` pointer field into RIP-relative LEA before lifting.
Verify the current state rather than editing by these historical line numbers.

Read #17/#18/#19/#20/#22/#27/#30/#32/#33/#35, and relevant #28/#29/#13 context.
Do not restart their already implemented mechanisms.

## Required implementation

### 1. Establish the real shared symbol and expression model

Use the metadata-first Link/SymbolicExpression design already specified in
`research.md` section 5.3. Evolve existing shared types; do not add a competing
module-only address convention.

- Identify a reference's origin and target by stable symbol identities,
  including source module/host provenance. Host source RVAs remain source
  coordinates, not global identifiers for all modules.
- Distinguish ordinary integer constants, module-local symbol addresses,
  image-relative expressions, host image-base expressions and external/import
  targets. Include signed addends and relocation field semantics.
- Carry address provenance through lifting, SSA construction, copies/phis,
  optimization, selection and final encoding. Extend/evolve the existing
  address operation rather than adding another numeric pointer heuristic.
- Preserve supported label-plus-addend and relative-field expressions. Model
  composite relationships required by real producer/consumer pairs; do not
  flatten them into guessed absolute values or invent unused future types.
- Preserve x64 REL32 biases and negative raw addends for trailing immediates.
  Host `__ImageBase + offset` is not a pointer into the module's own image.
  Binding the host image base does not freeze every offset forever: when an
  authoritative expression denotes an identified movable host object, retain
  that object's identity and interior offset for final rebasing. Preserve true
  header/base anchors. Unresolved computed address consumers constrain movement;
  never infer the missing relationship from arbitrary equal-valued integers.
- Retain compiler-authored boundaries/addends and validate them against the
  specialized DLL. Native compiler symbols/relocations remain authoritative;
  literal equality, section names or decoder confidence cannot prove a pointer.
- Replace synthetic-RVA namespace reservation/envelope logic as the authority
  for binding modules. Do not replace it with a larger reserved address range,
  UUID encoded into a constant, marker tags or another numeric namespace hack.
- Remove MOVABS-to-LEA byte normalization as a workaround for lost IR
  provenance. The real lifter/backend must consume the exact reference at its
  operand and choose a correct final encoding, including PIC where applicable.
- Treat encoder-local branch labels separately from link-time symbols. Local
  labels may serve encoding, but cannot substitute for address provenance.

A symbolic relocation is not evidence that all host references are known.
Preserve conservative host completeness/placement constraints. No function is
made movable simply because all discovered references are representable.

### 2. Make call contracts explicit for authored code

The exact callback boundary is Win64 `extern "system"`; that does not prove
that every compiler-generated internal Rust call has that ABI.

- Reuse existing shared signature/call-convention infrastructure and the
  Win32metadata/CRT/inference precedence. Do not duplicate the DB or remove
  sound conservative behavior for unknown host calls.
- Add real producer-to-consumer ABI/type metadata where needed for accepted
  authored calls. Include argument/return locations, classes, aggregate/sret
  behavior, clobbers and nonreturning behavior as required by actual code.
- Do not infer ABI from mangled names, assume Rust ABI stability, or claim a
  four-GPR/RAX default is proof for floats, aggregates or internal Rust calls.
- Implement producer and consumer together for each new contract. If the
  compiler metadata strategy requires a genuinely different toolchain design,
  research it and resolve that design with the user before a silent shortcut.
- Verify existing internal scalar dependency calls and focused nontrivial
  signatures. Prompt 3 expands the std/runtime acceptance matrix using this
  contract; it must not need a new parallel ABI system.

### 3. Build once from all inputs

Create one link plan with explicit ownership, constraints and final-address
resolution. Reuse existing layout/rewrite/rebuild components rather than
writing a replacement PE emitter.

- Parse/analyze the host and parse authored provenance before final layout.
- Prepare host/module functions through the same SSA/transform/codegen path;
  source provenance changes eligibility rules, not instruction semantics.
- Include module data/BSS, existing generated entry/translation/CFG helpers,
  imports, unwind, debug and loader relocations in the same plan.
- Resolve layout-dependent sizes through an explicit bounded/convergent layout
  process; branch expansion cannot overwrite a neighbor or depend on guessed
  final sizes.
- Emit the output image once, with one final active Exception table and one
  coherent BaseReloc description. Rebuild other required directories against
  the same final placement. There must be no intermediate host-only PE that is
  re-parsed as a module-placement prerequisite.
- Use explicit retained/resident/generated/retired ownership. A final table may
  legitimately include retained host records; it must not preserve a redundant
  host-only generated table solely because the old second stage emitted one.
- Keep module data permissions and zero-fill semantics. Do not serialize all
  BSS as file-backed zeros merely because that is convenient for the layout.
- Maintain raw/file-offset mapping for Debug, certificates/overlay and other
  consumers of file coordinates. Do not confuse RVA movement with raw repacking.
- Keep existing CFG non-enforcing policy, cookie semantics, export/TLS/debug
  rebasing and optional section names correct.

Prompt 3 replaces the hand-generated startup loader with compiled Rust module
code. In this milestone, existing generated helpers may remain real inputs to
the single plan; do not create temporary parallel layout/emission APIs for them.
Do not claim the loader composition gap is closed before that cutover.

### 4. Correct configuration and reporting contracts

Do not implement new protective passes just to make the schema appear complete.

- Process supported pass requests in declared order. Multiple supported MBA
  entries must not collapse to the first one.
- Unsupported enabled pass/settings requests must produce explicit contextual
  errors rather than successful output that ignores them. Keep first-profile
  ownership/selection rules explicit and test precedence.
- Semantic identity flags control semantic transformation. When a profile is
  supplied, they must not silently discard nonsemantic settings such as module
  injection, section naming or requested layout policy. Resolve conflicting
  selectors/flags explicitly. Identity without a profile must retain its
  documented behavior.
- Distinguish selected, eligible, lowered and actually transformed functions.
  Until Prompt 2 removes pressure-driven intensity reduction, report the actual
  intensity honestly; do not present identity fallback as full transformation.
- Replace fake module source RVAs in public maps/reports with explicit origin
  and source-symbol information. Host RVA/VA selector semantics must remain
  unambiguous. If a map schema changes, migrate all callers/tests/docs with a
  documented clean cutover, not compatibility aliases or mislabeled numbers.
- Preserve qualified `plugin::symbol` targeting, groups, deterministic ordering,
  contextual filesystem errors and exclusion/selection precedence. Do not
  manufacture empty CFG functions just to reuse a selector API.

## Acceptance: prove the real model and preserved pipeline

All acceptance below is required, not a menu:

1. Existing identity corpus remains green with honest stable-population
   coverage/rejection reporting. No new blanket reject to hide a regression.
2. Both ordinary host-only protection and module-enabled protection use the
   single final plan/emitter. A final protected artifact contains no redundant
   generated host-only Exception table caused by an intermediate rebuild.
   Check active directory targets, record ownership and source contributions;
   section count alone is not a valid assertion.
3. Real Rust modules from the producer build and execute in EXE and DLL targets
   in both current entry modes. Ordered callback effects, arguments, return
   value, forced ASLR and native unwind still pass.
4. Address regressions cover equal-valued literals versus pointers; duplicate
   source RVAs in different modules; signed addends; data interiors; ImageBase
   plus positive/negative offsets; trailing-immediate REL32; MOVABS pointer
   operands; copies/phis/optimization; and checked range/encoding errors.
   Symbols are resolved by identity, not by synthetic namespace coincidence.
5. Calls across authored functions/dependencies preserve the tested integer,
   floating-point and aggregate/return ABI cases supported by this milestone.
   Unsupported cases are not misclassified as safe by a guessed default.
6. A real profile-plus-identity invocation still performs configured injection
   while applying no semantic pass. Unsupported pass requests fail explicitly;
   supported ordered requests and selector precedence behave as documented.
7. Structure checks cover IAT/metadata references, data/BSS permissions,
   BaseReloc completeness, sorted/nonoverlapping runtime ranges, output maps,
   source provenance stripped from runtime output and preserved host behavior.

Use portable fixtures plus actual headless EXE/DLL execution. Read the master
verification rules; run all workspace gates once integration is ready. Do not
commit host-specific test paths or count mock callback invocation as proof.

## Handoff and non-goals

Update source-of-truth docs with the real new contracts and preserved limits.
Commit green milestones atomically, never push. Report the exact symbol,
reference, ABI, helper and final-layout interfaces that Prompts 2-4 must reuse.

Do not claim frame/pressure recovery, std completeness, compiled SDK loader or
whole-image compaction are delivered by this prompt. Those have explicit next
owners. Do not leave an old parallel path, shim or "later migrate callers"
branch under the guise of preserving compatibility.
