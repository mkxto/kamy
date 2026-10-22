# Prompt 4 — Whole-image virtual compaction and campaign acceptance

Implement after Prompts 1-3. Read `docs/handoffs/00-master.md`, all predecessor
prompts, their actual code/contracts and their measured handoffs. Reuse the
single symbol/reference graph, shared backend/frame model, complete module
runtime inputs and final image emitter. Do not build a separate rewriter or
re-analyze an intermediate emitted PE to obtain compaction inputs.

## Completion notice

**Status: Pending; no completion accepted.** Assigned issue scopes are the
whole-image layout/reference portions of #17/#18/#19/#20/#22/#27/#30/#33/#35,
consuming the completed SDK/runtime and frame contracts. These are assignments,
not claims of work performed. On completion, replace this notice with the
issue-by-issue work/evidence/residual ledger, accepted commits and successor
contracts required by the master's
[completion contract](00-master.md#completion-notices), and update its register.

## Goal

Deliver real whole-image virtual compaction as an explicit supported layout
mode, alongside the correct selective mode. This means moving eligible
surviving code/data and rewriting every affected reference/loader structure,
not just shrinking raw files, erasing old function bytes or truncating one tail.

The user specifically selected this capability to exercise deeper correctness
of the model. It does not authorize guessing pointers, disabling safe-rejects,
forcing unsupported code through, or treating passing tests as proof that an
unknown consumer does not exist.

## Read and baseline

Read #17/#18/#19/#20/#22/#27/#30/#33/#35 and their comments. Separate observed
CD layouts from guarantees: selective DLL builds can legitimately retain a
large `.text`; section counts/names are not invariants; the reference itself
records a stale original `.reloc` section.

Inspect the actual unified link plan, reference binding, directory ownership,
mutable image rebuild, retirement/reuse constraints and semantic/movement
selection policy left by the preceding prompts. Old sources included
`crates/kamy-link/src/{layout,rewrite,translation}.rs`, `lib.rs`, `module.rs`
and PE `rebuild.rs`/`rewrite.rs`/reference/directory parsers. Follow current
symbols rather than assuming those files still own the same concerns.

Baseline both selective and module-enabled outputs, code/data placement,
active directory graph, meaningful live bytes, padding/unreused ranges, image
virtual size, raw size, actual transformations, eligibility and rejects.
Historical section count or entropy alone is not an acceptance oracle.

## Required implementation

### 1. Express movement and pinning in the existing plan

- Keep source identity, semantic-transform selection and movement eligibility
  distinct. Do not override function exclusions/RVA selectors or security/
  loader constraints merely because a global mode was requested.
- Record why each object/range is retained, movable, generated, dead or pinned.
  Include incoming/outgoing expressions, data ownership, aliases, interior
  labels, opaque consumers, encoded directory relationships and section-index
  dependencies where applicable.
- Use metadata-first host completeness and exact authored module provenance.
  A known discovered-reference set alone is not proof of full completeness.
- Move code only through the supported shared lowering/reference path. Do not
  revive verbatim relocation for unsupported survivors to claim a whole image
  was compacted. Unsupported semantic/EH/reference constructs remain real
  constraints and may make the requested mode unavailable for that input.
- Preserve approved address translation only where its actual consuming path
  is rewritten. Original-address keys are not entry thunks; opaque consumers
  do not become safe because a translation table exists.
- Validate compatible selectors/layout requests explicitly. If a requested
  whole-image layout cannot be achieved with the applicable constraints,
  return an actionable failure before claiming success. Never silently switch
  to selective mode, relax constraints, or rename a partially packed result
  "whole-image compacted."

Do not require every arbitrary stripped PE to compact. Do require actual
whole-image success on completeness-proven fixtures and supported real
inputs, with explicit negative cases for unprovable inputs.

### 2. Plan all affected virtual and raw placement once

- Extend the same placement engine to pack eligible original code, resident
  survivors that can now move, data, generated helpers, Rust runtime/module
  objects, tables and directories at their final RVAs.
- Preserve original identities while locations change. No re-detection of
  references from final numeric byte values, arbitrary VA/RVA scans used as
  proof, or second namespace/binding layer.
- Support legal alignment, permissions and loader geometry. Distinguish virtual
  movement, raw repacking, data initialization and zero-fill. Keep Section-
  Alignment adjacency, file alignment, section bounds and image-size fields
  internally correct. Do not remove mapped coverage while later RVAs stay
  fixed and call the resulting gap a shrink.
- Resolve layout-sensitive instruction sizes/branch ranges and generated
  metadata to a sound final placement. Out-of-range RIP/rel32 targets must be
  encoded with a supported correct mechanism or rejected specifically; never
  truncate displacement fields.
- Preserve host/module image-base expressions, data-interior addends, original
  caller-frame semantics, import references, entry/export/TLS callbacks and
  runtime-generated pointers. Absolute pointer fields retain required loader
  fixups under ASLR.
- If section headers are removed/reordered/retyped, handle every affected
  section-ordinal or file-offset consumer. In selective mode, maintain pinned
  survivor RVAs and ordinal guarantees. Do not apply whole-image freedoms to
  the selective path implicitly.
- Account for PE headers, resources, load configuration, certificates/overlays,
  debug/file pointers and supported opaque encodings. Preserve or reject an
  unsupported structure explicitly rather than silently corrupting it.
  Modifying an image invalidates its old Authenticode authentication; preserving
  certificate bytes is not preservation of a valid signature.

### 3. Rebuild one canonical active directory graph

- Rebuild/rebase all affected Import/IAT/Export/Exception/xdata/BaseReloc/TLS/
  LoadConfig/Debug structures and supported additional metadata from the
  authoritative final layout. Preserve names/ordinals, forwarding semantics,
  callback/initialization order, runtime-function ownership and actual frames.
- Emit one final active description for each directory. Remove unnecessary
  intermediate generated host-only tables; do not leave the old two-stage
  architecture's `.pdata`/relocation copies behind.
- Check header relocation policy as well as directory bytes, including newly
  required fixups in an originally fixed/relocs-stripped image. BaseReloc
  `(RVA,size)` must agree when empty; do not leave a nonzero RVA with zero size.
- Maintain the explicit non-enforcing CFG default and correct cookie references.
  Do not claim enforcing module CFG/longjmp/SAFESEH or ACG compatibility without
  an actual implementation and exercised gate; unobserved vendor extras are
  not prerequisites for this campaign.
- Preserve Debug/CodeView semantics as configured. Do not strip it or forge a
  placeholder to avoid resolving a file/RVA relationship.

### 4. Reclaim owned space, not merely change the fill byte

- Reuse proven-free ranges/section slots for real generated code/data/helpers
  where compatible with permissions, size/alignment, incoming references,
  unwind and loader ownership. Do not force every code object into a reclaimed
  original hole if it contradicts the primary-code-home plan.
- Treat the old Exception slot as one proven-reuse case, not a special-case
  sole recycling API keyed by the name `.pdata`. Reuse must depend on real
  ownership and consumer constraints.
- In whole-image mode, move eligible survivors so dead interleaved holes can
  actually disappear. Show the resulting relocated data/code addresses and
  final compacted extents; raw-size shrink alone is insufficient.
- In selective mode, exploit safe in-place reuse and proven dead tails without
  sliding unresolved survivors. Remaining alignment/free padding is permitted
  and measured, not counted as useful reclaimed code.
- Avoid INT3 or NOP floods masquerading as clean rebuilding. Ordinary bounded
  instruction/alignment padding is legitimate; it is not a new decoy/strength
  pass and not proof of natural-looking entropy.
- Retire old bytes only when ownership is proven and no live consumer pins
  them. Original stale directory blobs may legitimately remain; do not delete
  them merely because the observed CD layout usually looks cleaner. Quantify
  what remains and why. Do not confuse inactive bytes with active stale
  descriptions or unnecessary generated duplicates.

## Required acceptance matrix

All items are required, with meaningful independent execution/state oracles:

1. A completeness-proven host fixture contains interleaved movable code,
   surviving code and data, both-direction rel32/RIP references, absolute
   pointers, image-relative fields, taken addresses and interior-data labels.
   Whole-image mode changes survivor RVAs, removes the interleaved dead space,
   executes correctly and contains no original-entry detours/verbatim fallback.
   Do not use a fixture where all survivors already form a removable tail.
2. Exercise imported functions/data, moved exports and entry, TLS callbacks/
   storage, module/runtime initialization, resources and supported debug/load-
   config structures. Multiple Rust modules plus the host must share the same
   final plan, ordinary imports and Exception/relocation descriptions.
   Include a module referencing host data that itself moves: a base-relative
   address must not keep an old host RVA merely because its `__ImageBase`
   anchor still binds correctly. Check header-relative accesses separately.
3. Prove real `.text`/data virtual compaction separately from raw repacking:
   track old/new source identities, actual RVAs, live extents, padding/free
   bytes, final directories and file offsets. Do not use section count or a
   renamed section as the sole proof of compaction.
4. Create negative fixtures with opaque/unresolved incoming references,
   unsupported metadata or a pinned survivor that prevents the requested global
   layout. The request fails concretely and does not silently write a selective
   result. The same input may still succeed explicitly in selective mode.
5. Reuse an eligible old section/range with a real consumer. Include pinned,
   partly owned, nonzero-tail, overlapping-directory and capacity/alignment
   counterexamples that must not be reused. Verify actual loader execution and
   unwind for recycled executable storage.
6. Force ASLR on EXE/DLL outputs where supported. Verify all required absolute
   fixups, host/module references, correct headers, exact DLL args/result and
   native Windows unwind through moved frames/compiled SDK loader. Exercise
   the supported fixed-base/relocs-stripped policy explicitly.
7. Preserve process-attach-only DLL user initialization, original DllMain
   notifications and TRUE/FALSE behavior; keep host/module TLS and teardown
   correct after compaction. No claim of support for incomplete manual mappers.
8. Re-run Prompt 2's combined pressure witness, large-frame/call/recursion cases
   and Prompt 3's std/dependency/import/self-resolver cases on the final layout.
   Add genuinely new layout-edge regressions; do not duplicate tests of wiring.
9. Full identity corpus remains green in selective mode. Exercise whole-image
   mode on the supported corpus subset with explicit per-input eligibility;
   report whole-image rejects, not successful selective fallbacks. Run actual
   transformed profiles too, since the ordinary corpus is an identity gate.
10. Confirm configuration/pass/selector behavior remains explicit, supported
    requested intensity is not reduced, unsupported requests fail, maps carry
    honest origins and output evidence distinguishes lowering from protection.

Provenance-complete fixtures establish that the global mechanism works; they
are not proof that every stripped production image has complete references.
Do not adjust goldens or broaden rejects to conceal newly exposed miscompiles.
Follow headless triage to isolate and repair their causes.

## Final campaign delivery

Run the master's workspace gates, actual scenarios and structural checks. Keep
all affected callers/tests/docs consistent; delete obsolete alternate layouts,
retirement shims, encoder workarounds and stale comments after cutover.

Commit green milestones atomically, never push. Deliver an evidence-backed
capability matrix:

- Selective versus whole-image mode, eligibility, movement and rejection causes.
- Host inferred versus authored compiler reference provenance.
- Supported Rust std/runtime/ABI and ordinary/self-resolved import paths.
- Concrete frames, memory-backed allocation, requested/actual transformation.
- Entry/TLS/DLL lifecycle and unwind guarantees actually exercised.
- Which portions of #17/#27/#32/#15/#6/#5/#9/#10/#13/#16 are satisfied and which
  semantic/protection work remains. Do not close a whole issue for a subset.

State remaining limitations without "CD-equivalent", "100% coverage" or
"everything fixed" claims unsupported by the exercised matrix. Do not narrow
this assignment to just a cleaner section table or another callback smoke.
