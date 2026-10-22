# Prompt 3 — Rust std-capable SDK and compiled module startup

Implement this assignment after Prompts 1 and 2. Read
`docs/handoffs/00-master.md` and both predecessor prompts, then their actual
code, changed contracts and exercised evidence. Reuse their unified symbols,
frame/memory-backed backend and single rebuild. Do not revive the old module
append stage or synthetic address namespace.

## Completion notice

**Status: Pending; no completion accepted.** Assigned issue scopes are
#32/#27/#35, with #18/#19/#20/#30/#33/#13/#28/#29 integration and bounded
#11/#12/#26 prerequisites. These are assignments, not claims of work performed.
On completion, replace this notice with the issue-by-issue work/evidence/residual
ledger, accepted commits and successor contracts required by the master's
[completion contract](00-master.md#completion-notices), and update its register.

## Goal

Complete the agreed Rust SDK extension model: compiled Rust module functions
and data, including the startup loader, enter the same native rewriting
pipeline as host code. Support ordinary imports and self-resolving modules,
Rust `std` with `panic=abort`, required module runtime/TLS initialization and
correct target entry lifecycle.

The prior no_std-only/dirs-3-and-5-only implementation is not the endpoint.
This is not permission to claim every possible Rust crate or all language EH
works. State a concrete supported feature/ABI matrix, and satisfy all acceptance
cases below without simplifying the programs to avoid missing prerequisites.

## Read and preserve

Relevant issues: #32/#27/#35, #18/#19/#20/#30/#33, #13/#28/#29 and prerequisite
parts of #11/#12/#26 where real runtime output requires them. The larger
semantic/EH backlog remains separate.

Starting areas:

- `crates/kamy-sdk/src/lib.rs` and its build/entry macros.
- `crates/kamy-cli/src/commands/{plugin,protect}.rs`, CLI/config/targeting.
- `crates/kamy-pe/src/module.rs`, `src/module/{producer,coff,tests}.rs`.
- The unified module/link/ABI/frame plan left by Prompts 1 and 2.
- PE imports/exports/TLS/load-config/debug/unwind and final directory emission.

Preserve the real Cargo dependency closure, compiler-authored native provenance,
signed expressions, module data/BSS, qualified profile targeting, address maps,
ASLR fixups, supported native unwind, inline/table entry modes and the off-by-
default/kernel-excluded policy.

## Required implementation

### 1. Compile the loader as Rust SDK module code

The previous loader is a hand-generated iced-x86 instruction vector emitted
outside SSA. Replace that path; do not retain it as a fallback when Rust lowering
gets difficult.

- Compile the init-table loader as authored Rust code with its real code/data
  symbols, ABI contract and authoritative references. Linker-supplied table
  bounds and entry symbols are real producer/consumer relationships.
- The loader, callback functions and required dependency functions must be
  eligible for the same configured supported passes, memory-backed lowering,
  final placement and actual-body unwind as other code.
- Keep EXE table ordering `[plugin callbacks..., original entry]` within the
  declared half-open bounds. The original entry is the final in-range
  continuation; never call an out-of-range slot. A returning EXE startup is an
  explicit contract failure, not a past-end fallthrough.
- Inline sequencing calls the configured callbacks, restores the original
  entry context and tail-transfers to the original entry. Do not introduce an
  extra call-original frame merely to simplify a failure branch.
- Forward the original RCX/RDX/R8 entry values; these are not main's
  argc/argv/envp. Preserve Win64 stack/return behavior and nonvolatile state.
- Callback status zero continues; nonzero preserves the actual callback status
  into fast-fail. Do not replace every status with a generic constant.
- Respect CET/shadow-stack call/return invariants and indirect-entry landing
  requirements. A minimal backend ABI/CET adapter is allowed only when
  necessary and explained; it cannot contain a parallel untransformable loader.
  Do not delete a necessary landing bridge just to claim zero helper stubs.
- Remove obsolete hand-loader code, tests that pin its incidental instruction
  spelling, and unused startup-table/helper emission after the cutover. Keep
  behavioral regressions for arguments, ordering, status and unwind.

### 2. Support ordinary module imports through the unified linker

- Parse module import provenance and resolve/rebuild it with host imports.
  Do not leave copied module RVAs in descriptors or put the native module DLL
  on a runtime LoadLibrary path.
- Handle named/ordinal imports, duplicate libraries/symbols, imported functions
  and imported data, correct IAT ownership/permissions, and module references
  to their final slots. Preserve the host's existing import semantics.
- Bind new references from real compiler/linker metadata. Do not scan arbitrary
  qwords or materialize addresses as ordinary constants that transforms can
  lose. Use shared ABI/type information for imported calls.
- Keep bound/forwarded/API-set and supported loader semantics explicit; a name
  that cannot be recovered must fail contextually, not become a fake API stub.
- Retain the ability to link import-free modules that resolve APIs themselves.
  Deliver and exercise a Rust SDK-supported resolver path or maintained Rust
  dependency with real module/export handling. No copied/vendor source,
  C/C++ plugin utility, mandatory hash-hiding pass or hardcoded process address.
- Verify a real self-resolved Windows API call without adding its import through
  the module. The reference's particular MurmurHash constant is sample
  evidence, not a requirement to clone its hashing implementation.

Ordinary imports may intentionally add output dependencies/IAT entries;
self-resolution may intentionally avoid them. Report the chosen behavior,
not a blanket "host IAT unchanged" claim for every configuration.

### 3. Support std and the runtime it actually requires

The public authoring language remains Rust. Native Windows ABIs/imports and
compiler-generated native objects do not imply a C/C++ plugin surface.

- Support actual Cargo dependencies and the native LTO/static linking closure,
  not only a leaf file with inlined helpers. Do not feed bitcode into a COFF
  parser or drop unresolved runtime objects to make packaging succeed.
- Inspect the real compiled artifact's imports, TLS, initialization/termination
  data, exception/unwind records, exports and linker directives. Implement
  the required producer and consumer semantics. Do not whitelist a directory
  number while failing to service its runtime obligations.
- Merge supported module data-directory semantics into the target's final
  structures. Preserve unmerged directory ownership in the SDK artifact;
  regenerate runtime structures rather than copy stale module directories.
- Preserve zero-initialized data, mutable statics, read-only data, alignment,
  relocation-backed pointer fields and compiler-generated address expressions.
- Implement needed initialization/teardown registration and TLS storage/index,
  callback and destructor behavior. Multiple modules must not share an
  accidental TLS index, alias template offsets or initialize twice.
- Preserve host TLS callback order/behavior. Module initialization must satisfy
  its own dependency order; adding it must not delete/reorder host callbacks
  to make the test pass. Document the exact combined startup/teardown order.
- Ensure imported native runtime dependencies are initialized appropriately.
  Do not assume Windows or the host's CRT has initialized a separate statically
  incorporated runtime merely because execution reached the host entry.
- Keep panic=abort explicit. Panic handling must not acquire an accidental
  second panic implementation or pretend to provide catch/unwind support.
- Carry actual internal Rust ABI contracts for dependencies. Test returns and
  arguments beyond a scalar integer; never extend the Win64 default by guess.
- Implement narrowly necessary SSA operations/flags/segment/runtime semantics
  required by the acceptance matrix, with real effects and isolated regressions.
  This is explicitly authorized prerequisite work, not a reason to reject the
  promised std cases or to expand into all of #11/#12.
- For module exports, use deliberate SDK/compiler symbol metadata and regenerate
  intended output exports through the unified model. Do not copy `.edata`,
  expose every internal Rust symbol, or use a second PE/linker path. Include
  the actual export surface needed for post-load SDK operation testing.

A documented limitation on unrelated unsupported crates/ISA/EH remains valid.
It cannot be invoked to call the explicitly promised feature matrix complete
while those features still fail.

### 4. Correct DLL-target lifecycle without inventing hidden triggers

The target itself may be an EXE or DLL. The packaged plugin DLL is only an
artifact; do not confuse its PE entry with the target's actual entry lifecycle.

Use the observed H1 follow-up failure as an early regression for this cutover.
A native probe loaded the protected ordered DLL, then directly invoked its real
target entry with thread-attach and thread-detach reasons. The observed trace
records callback effects, not merely original DllMain visitation:

| Entry event in sequence | Observed H1 trace | Required trace after this handoff |
|---|---:|---:|
| Process attach through LoadLibraryW | 12 | 12 |
| Direct entry call with DLL_THREAD_ATTACH (2) | 1212 | 12 |
| Direct entry call with DLL_THREAD_DETACH (3) | 121212 | 12 |

Turn this into a portable committed fixture with Windows execution gated
appropriately. Exercise actual Windows thread/unload notifications as well as
direct reason calls; a direct call alone does not prove OS lifecycle ordering.
Check that user initialization does not repeat, while the original DllMain
still observes every notification, exact arguments and its real TRUE/FALSE
behavior. Include process detach and unload/reload in the lifecycle matrix.
This is an outstanding requirement, not acceptance supplied by H1's green
identity corpus or generated-loader argument/unwind checks.

- On EXE startup, execute configured initialization before the original entry,
  with the native TLS/loader ordering accurately documented.
- On a DLL target, initialize plugins only when the entry receives
  `DLL_PROCESS_ATTACH`. Thread attach/detach and process detach must still
  reach the original DllMain with correct original arguments and return value,
  but must not rerun user initialization.
- Preserve the original DllMain BOOL result, including FALSE/failure handling.
  Never status-check successful TRUE as though it were an init status.
- Runtime teardown/TLS obligations are distinct from rerunning the user init
  callback. Service the actual adopted runtime semantics with explicit ordering;
  do not silently leak required cleanup or run the init table during unload.
- Hook the target entry, not LoadLibrary. A manual mapper that supplies the
  required imports/relocations/TLS and calls the entry with process-attach can
  use the same path. Do not build a mapper, assume incomplete mappers work,
  or invent a hidden polling/thread mechanism to detect "real load."
- DLL entry runs under loader-lock constraints when Windows calls it. Document
  them. Do not spawn/wait for a worker or delay initialization to escape them.
  Test thread-dependent std operations after attach returns, via a real SDK
  export/target call; do not call loader-lock-unsafe code in DllMain and label
  hangs a protector bug or silently move it to a different phase.

### 5. Preserve explicit configuration and fail atomically

- Keep injection disabled by default, ordered named plugins, relative profile
  paths and qualified selectors. Identity flags must not erase injection or
  other nonsemantic settings supplied by a profile.
- Preserve Prompt 1's ordered supported pass behavior and explicit rejection
  of unsupported pass/settings requests. Do not implement a new strength
  catalogue to fill schema checkboxes.
- Failure of a required module/function/runtime obligation fails the requested
  output before claiming success. No omitted callback, byte-copy fallback,
  identity-intensity substitution, partially written successful image, or
  blanket safe-reject of module functions.
- Report module/host origins, actual transforms, frame/memory-backed use and
  real dependencies. No synthetic source-address map disguised as host RVAs.

## Required acceptance matrix

Use Rust-authored plugins and deterministic portable host/loader fixtures.
C/C++ host fixtures are permitted where they test host behavior, not as an
alternate plugin implementation. Run actual outputs through `kamy-run`.

1. Existing no_std plugins still build and run through the clean shared path.
   Two ordered callbacks and the compiled loader are genuinely transformed
   under a supported profile, not merely reported as visited by a callback.
2. A real std plugin exercises heap allocation, owned strings and collections,
   mutable/read-only/BSS data and a non-inlined dependency call. Check values
   after initialization, not just successful loading or a nonempty output.
3. Exercise real supported std I/O/environment/runtime operations in isolated
   deterministic scenarios with owned temporary resources and explicit cleanup.
   Do not use network access or interactive dialogs as the oracle.
4. Exercise supported std synchronization, thread-local initialization and
   destruction, and thread creation/join outside DLL entry's loader lock.
   Check distinct per-thread state, initialization counts and destructor effects
   where applicable. Include multiple injected modules and existing host TLS.
5. Ordinary Windows API imports resolve correctly alongside existing host
   imports, including a real imported-data or equivalent supported compiler
   import case. A separate self-resolving Rust module calls a real safe API
   without introducing that module import. Validate structure and runtime.
6. EXE inline and init-table modes preserve original behavior and ordered effects;
   original startup remains the final valid continuation. Nonzero callback
   statuses stop startup with the expected failure behavior, never execute a
   past-end slot and never lose the status value.
7. DLL modes preserve exact hinst/reason/reserved and TRUE/FALSE outcomes.
   Create/exit threads, unload/reload the DLL and verify user init is called
   once per process attach, never for thread/unload notifications. Teardown
   and module/host TLS behavior remain correct; no hidden worker performs init.
8. Force ASLR. Use Windows native runtime-function lookup/unwind through the
   compiled loader and allocated module frames, including nonvolatile GPR/XMM
   recovery and relevant call/return states. Check complete fixups and guard/
   cookie consistency, not just PE reparsing.
9. Test both a relocs-stripped/fixed-base host and a normal relocatable host.
   When new runtime fixups are introduced, output header flags and directories
   must agree with the supported relocation policy. Do not ignore the old
   `IMAGE_FILE_RELOCS_STRIPPED` edge or claim it is broken without exercising it.
10. The combined bounds-check/counter witness from Prompt 2 works intact under
    the full SDK pipeline. No regression to sample-sized callbacks.
11. Profile+identity still injects without semantic transforms; disabled
    nonexistent plugin paths remain unread; unsupported requests fail with
    actionable context and no false-success artifact.
12. Full identity corpus remains green, plus explicit transformed/module
    execution scenarios. Report eligibility, real protection and execution
    separately. Do not re-bless protected misbehavior.

The public supported std/ABI/runtime matrix must be concrete and tested.
Passing a leaf callback, having std present in a dependency graph, or compiling
an object without running it does not satisfy std support.

## Handoff

Apply the master's gates/atomic commits; never push. Update SDK/tooling examples,
architecture and status to the actual expanded contract. Remove obsolete
no_std-only/dirs-only/hand-loader restrictions after their real replacement
lands; keep precise limits that are still true.

Hand Prompt 4 the complete single-plan host/module/runtime graph, directory
ownership, ABI/frame contracts, retained source constraints and real fixture
set. No intermediate SDK-specific rebuild or hidden runtime fallback may remain.
