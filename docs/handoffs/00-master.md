# Rebuild, allocation and Rust SDK repair campaign

## How to use this handoff

Read this file with each numbered prompt. Execute the prompts in this order:

1. [Unified symbols and single rebuild](01-unified-rebuild.md)
2. [Concrete frames and memory-backed lowering](02-memory-backed-lowering.md)
3. [Rust SDK, standard library and entry lifecycle](03-rust-sdk-runtime.md)
4. [Whole-image virtual compaction](04-whole-image-compaction.md)

Each numbered file is a runnable agent assignment, not permission to call an
intermediate architecture the finished campaign. The next assignment consumes
its predecessor's real implementation and evidence. Do not restart completed
work or create a second convention for the same concern.

No implementation was performed during the grilling session that produced
these instructions. This file records the user's confirmed direction. It is
not evidence that any future milestone has passed.

## Confirmed user decisions

These decisions were explicitly selected or confirmed during the grilling
session:

- Produce separate, ordered implementation prompts rather than one undivided
  assignment. The confirmed order is the four stages above.
- Repair the listed architectural shortcuts. The target is a solid native
  bin2bin rewriter with statically linked SDK modules, aligned with the observed
  CodeDefender design, not merely a runnable callback demo.
- SDK/plugin authoring remains Rust-only. C/C++ targets remain legitimate host
  inputs and test fixtures; that does not authorize a C/C++ plugin surface.
- Support ordinary module imports alongside modules that resolve APIs
  themselves. A hiding/hash pass is not mandatory, and the host IAT need not
  remain untouched when ordinary imports are explicitly used.
- Support Rust `std` with `panic=abort`, not only freestanding `no_std` modules.
  Include narrowly necessary operation/runtime prerequisites for the promised
  SDK acceptance cases. Broad ISA expansion and language unwinding remain a
  separate semantic-coverage track.
- Follow CD's memory-backed-intermediate model as the lowering baseline:
  bounded scratch-register working sets, explicit flag state, correct frame
  reconstruction. Pressure must not force rejection or reduce the requested
  transform intensity for otherwise supported functions. Register-resident
  optimization may avoid unnecessary memory traffic without weakening this
  guarantee.
- For DLL targets, default initialization runs on `DLL_PROCESS_ATTACH`, before
  the original entry. Do not run it again on thread notifications or unload.
  This hook is the target entry itself, not interception of `LoadLibrary`.
  A manual mapper that invokes the entry with that reason can exercise the
  same hook; no compatibility promise covers a mapper that omits required
  imports, TLS, relocations or entry invocation.
- Include whole-image virtual compaction, not just raw repacking or trimming a
  dead tail. It must rewrite all affected references and structures. If the
  requested global layout cannot be justified, fail that mode with a specific
  reason; do not silently emit a selective result and call it compacted.
- Protective-pass strength is not the current priority. Preserve the existing
  MBA baseline. Honor supported configuration or reject unsupported requests
  explicitly; silently ignoring a configured pass is not acceptable.

The implementation agent MUST record the relevant policy changes in the next
available numbered decision entry before implementing them. Reconcile D5,
D28, D37, D38 and D39 and the architecture/research text. The user's decision
supersedes the old zero-spill prohibition; do not leave incompatible policies
simultaneously binding. This does not supersede safe rejection of unresolved
host references or permit verbatim-relocation fallbacks.

Do not treat all prior implementation restrictions as user approvals merely
because they were written into docs during the previous build. In particular,
`no_std`-only support, the hand-generated loader and the second module rebuild
were implementation choices, not the desired endpoint.

The user confirmed this plan after grilling. Do not restart the interview or
ask for approval of these settled choices. Research repository-provided facts
directly; escalate only a genuinely new conflict or material design tradeoff.
Complete the assigned prompt's acceptance before yielding, not merely its
baseline, plan, first commit or an easier subset.

## Read before editing

Follow the repository's loaded operating guide. Read:

- `docs/grilling.md`, especially D5, D16, D22, D24 and D28/D37-D39.
- `docs/architecture.md`, especially the rebuild and authored-module contracts.
- `docs/research.md`, particularly register/frame research and section 5's
  metadata-first symbolic-reference model.
- `docs/code_defender.md`: transform versus inject; reference rewriting;
  section recycling; selective versus whole-image layout; memory-backed
  register model; entry handling; module code/data and linker provenance.
- `docs/STATUS.md`: its final relocation section is the current snapshot;
  earlier measurements are historical.
- `docs/tooling.md` and the `kamy-triage` skill when investigating miscompiles.
- The relevant issues and their comments, then the current source. Issue state
  and historical rejection counts are not an implementation inventory.

The CD document contains measured behavior, vendor claims and inference.
Preserve those distinctions. It is not a specification of every vendor build.
Do not impose a fixed section count/name, universal recycling, or an absent
feature based on one sample. It also explicitly records a stale original
`.reloc` section: old bytes alone are not proof of an incorrect rebuild.

## Issue map and reconciliation

Fetch current issue bodies/comments; the following is a navigation map, not a
claim that each issue is wholly unfinished.

| Track | Issues | Reconciliation required |
|---|---|---|
| Reference/link/rebuild | #17, #18, #19, #20, #22, #27, #30, #33, #35 | Preserve the real thunk-free cutover; integrate symbols and final layout rather than replace it with another backend |
| SDK/entry modules | #32; #27/#35 dependencies | Rust-only static linking, compiled loader, ordinary imports, std/runtime and correct EXE/DLL lifecycle |
| Frame/allocation | #15, #6, #5; related #9/#10 | #15 is the concrete-frame prerequisite; #6's current pressure-bounded zero-spill thesis is not the newly agreed default; #5 mixes allocation and future MBA-strength work |
| Cheap allocation complements | #16, #13 | #13 already has a working DB/import-thunk/inference path; inspect and extend residual gaps, do not reimplement it |
| Broader semantics | #11, #12, #14, #26; residual #23 | Keep as a distinct track except required prerequisites for the explicitly promised SDK/frame cases |
| Naming/profiles | #28, #29, #34 | Reuse existing names, selectors, groups, xrefs, PDB work and section-name policy; fix contract behavior, not protective strength |
| Later protection strength | strength portion of #5 and future pass work | Do not expand this campaign into new nonlinear MBA/CFF/VM/import-hiding products |

Examples of stale issue statements to reject: verbatim relocation on failure,
`NoThunkSpace`, unwired callee-saved XMM pool, wholly absent Win32metadata, and
old crash diagnoses already corrected in #23. GPR/XMM resources are separate
register classes, not an interchangeable pool of "25 registers."

Do not close or rewrite remote issues wholesale during research. Reconcile
status locally with evidence; publish or close issues only when authorized,
and only for acceptance actually satisfied. Preserve partial/residual work.

## Starting implementation and evidence

Starting anchors, subject to intervening user changes:

- `d82267c`: native image rebuild and section reclamation.
- `1021714`: configurable Rust SDK/plugin linking.
- Last exercised workspace gates: fmt, clippy with denied warnings,
  workspace/all-target build, 225 tests.
- Last identity corpus: 23/23 PASS, 1,314/11,202 reported functions SSA-lowered,
  9,888 rejected, zero verbatim relocations, no `NoThunkSpace` rejects.
- That snapshot includes 1,740 `RegisterPressure` and 64 `CallerFrameAccess`
  rejects. Older counts such as 4,462/329 are historical, not target baselines.
- The earlier 21/23 baseline lowered 2,100 functions over a different reported
  population. Green execution was partly bought through conservative residency;
  it is not evidence of equivalent protection coverage or a repaired throw
  helper backend.

The existing corpus verifier uses identity protection. Keep reporting these
axes separately: execution verdict, eligibility/reference completeness,
SSA-lowered count, actual transforms/intensity, memory-backed allocation/frame
use, and per-reason rejection. An identity-lowered function is not proof of
MBA protection. A passing file is not proof every function was moved.

Actual exercised module scenarios included ordered callbacks producing
`trace=12` in EXE/DLL inline and init-table modes; exact DLL entry arguments and
TRUE return under forced ASLR; Windows native loader-frame unwind; linker-filled
bounds; a real non-inlined Rust dependency call; nonzero callback fast-fail;
disabled missing-plugin paths; and an integrity callback on `console_tls`.
These are narrow proofs, not arbitrary Rust/PE/ABI coverage.

A combined bounds-check/counter callback failed `RegisterPressure`. Splitting
it into independent smaller callbacks proved component behavior, not the
combined program. Recover and retain the combined case as a portable
before/after allocation acceptance witness; do not discard or simplify it.

Useful prior external artifacts may exist under
`C:/dev/kamy-corpus/protected` and baseline files under `C:/dev`. They are
optional investigation aids, never dependencies of committed tests. Discover
the current corpus/toolchain through repo configuration and tools. A new agent
has no retained Eval state or setup from the previous process.

## Preserve these working mechanisms

Migrate their callers cleanly when interfaces change; do not remove a safety
invariant simply because it limits coverage:

- Bidirectional direct/RIP reference rewriting, absolute and supported metadata
  rebasing, moved export rebasing, resident caller patching.
- No original-entry thunk per mover, no minimum thunk-size reject, no verbatim
  relocation path or fallback.
- Exact compiler-authored module symbol/relocation provenance. Specialized DLL
  input with dedicated directory ownership; native COFF is a build
  intermediate. Numeric literals never become pointers by value matching.
- Symbol base plus signed compiler addend, relative-field bias, host image-base
  binding distinct from module-local storage, data-interior references and
  equal-valued ordinary literals. LLVM REL32 may use a negative addend for
  trailing immediates; flattened expressions need not be valid standalone RVAs.
- D24 use-def DAG plus petgraph VF2 recovery, proven switch bounds, table-free
  lowering. Untouched switches retain their tables. Do not rewrite a surviving
  jump table to work around incomplete lifting.
- SSA construction, call-argument pin transfers, parallel-copy correctness,
  NativeInline operand/clobber modeling, BoolNot and partial-register fixes.
- Existing Win32metadata/CRT signatures, call-thunk resolution, callee inference,
  PDB/naming work, GPR/XMM save pools and fixed-base unwind offsets.
- Actual-body unwind generation and Windows RtlVirtualUnwind evidence. Frame
  changes must update the real encoded unwind semantics.
- Consistent non-enforcing CFG default and valid security-cookie references;
  enforcing CFG is not silently introduced.
- Optional section naming, identity/profile address maps and contextual errors.
- SectionAlignment-rounded mapped adjacency independent of raw tail removal.
- Known old-to-new translation only when its actual consumer uses it. This is
  an approved mechanism, not automatically a bandaid. Opaque consumers still
  constrain placement; a map alone cannot make them safe.

## Architecture boundaries across all four prompts

One shared symbol/expression model, one lowering backend, one frame model, one
final layout/rebuild. Host inference and compiler-authored module provenance
are distinct inputs to that model, not parallel implementations.

Shared, format-agnostic types belong in `kamy-core`; PE field layouts and loader
structure interpretation do not. Changes to exported symbols require reference
lookup and full caller migration. Remove obsolete APIs, synthetic-binding
workarounds, comments and compatibility aliases when their replacement lands.
Do not create types with no real producer and consumer.

If authored artifact or public map schemas change, version them explicitly,
rebuild all first-party fixtures and migrate consumers together. Reject obsolete
input formats contextually; do not keep compatibility branches that preserve
the broken address model. An in-memory type change is not proof that the
serialized producer and consumer still agree.

Prompt 1 establishes shared contracts before Prompt 2 changes frame/lowering
consumers. Prompt 3 integrates the complete SDK/runtime through those contracts.
Prompt 4 adds global placement to the same link plan, never a second compactor
that independently rediscovers references or re-emits the PE.

If a true dependency crosses this order, make it explicit and coordinate the
small prerequisite rather than making a temporary parallel path. Do not
silently expand into the entire semantic/protection backlog or silently remove
an agreed acceptance criterion. Resolve a genuinely new design tradeoff with
the user before diverging.

## No-bandaid contract

The following are prohibited:

- Name/RVA/fixture-specific allowlists, arbitrary numeric pointer sweeps,
  invented reference completeness or profile-dependent correctness.
- Tagging numeric constants with sentinel addresses and rediscovering
  provenance after optimization. Encoder-local block labels are not a license
  to use numeric values as the authoritative symbolic model.
- Silently ignoring configuration, unsupported passes, runtime features,
  callbacks, imports or exports; silent fallback from requested whole-image
  compaction to selective output; silently reducing requested protection to
  fit registers.
- Relocating unsupported functions verbatim, retaining original-entry stubs as
  a substitute for rewriting references, or removing legitimate loader fixups
  merely to mimic a zero-relocation statistic.
- Faking std support by changing the test to no_std; faking pressure recovery
  by splitting the failing callback; omitting constructors/TLS/runtime code
  that the compiled artifact actually requires.
- Hidden worker threads or deferred initialization to escape DLL loader-lock
  constraints. State the callback contract; preserve target lifecycle.
- Claiming all old bytes must vanish or every section must be repurposed.
  Prove ownership before reuse. Do not delete pinned original structures.
- Closing semantic/EH issues because rejecting their functions makes the
  corpus green. Regression containment is not root-cause repair.

Fail-closed eligibility is valid for genuinely unmodeled semantics/references.
It is not completion of a specifically promised acceptance case. If such a
case fails, fix its cause or obtain an explicit scope decision; do not replace
it with an easier demonstration.

## Verification and delivery for each prompt

Before changes, record a fresh baseline and preserve current user work. Do not
rerun a user-reported failure merely to dispute it. Reproduce changed-path bugs
with the headless tools and follow `corpus verify -> bisect -> dump --stage
regalloc`; x64dbg is only a deep dive after isolation, not a batch oracle.

Use deterministic portable committed regressions for consumer-visible bugs.
Run actual EXE/DLL outputs through `kamy-run`; forced-ASLR and Windows native
unwind checks are required where relevant. Tests alone are not runtime proof.
No host-system files or ephemeral local artifacts in permanent tests.

At each completed milestone run from the workspace root:

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo build --workspace --all-targets
cargo test --workspace
```

Also run the relevant corpus/identity/profile/plugin and structural scenarios.
Keep golden behavior unchanged unless the original oracle is independently
proven wrong. Compare a stable target population and rejection transitions;
report additions/removals instead of masking denominator changes. Never count
silently dropped functions as recovered coverage.

Before fan-out, establish shared types/contracts and edit ownership. Parallelize
independent slices, not competing edits to the same allocator/linker. Workers
skip builds/tests/formatters mid-flight; the integration owner runs the gates.

Commit green milestones atomically, imperative subjects, never push. Update
status/tooling/architecture with exercised evidence and intentional remaining
limits. Remove throwaway scaffolding from the repository. Do not rewrite the
vendor reference to match implementation shortcuts or claim unexercised parity.

A milestone report MUST state: changed contracts; preserved behavior; actual
commands/results; before/after eligibility and coverage; strict failures;
remaining risks; and the exact contracts/artifacts consumed by the next prompt.
