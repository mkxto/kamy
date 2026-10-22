# Prompt 6 — Windows x64 SEH and language-handler reconstruction

Read `docs/handoffs/coverage-extension.md`, `00-master.md` and the actual
predecessor implementations. Default execution follows 01-05. Do not change an
active predecessor's link/frame contracts or implement a second exception-only
layout/backend.

## Completion notice

**Status: Pending; no completion accepted.** Assigned issue scopes are
#12/#20/#23/#33 exception/handler reconstruction residuals, preserving existing
plain-frame unwind and predecessor frame contracts. These are assignments, not
claims of work performed. On completion, replace this notice with the
issue-by-issue work/evidence/residual ledger, accepted commits and successor
contracts required by the master's
[completion contract](00-master.md#completion-notices), and update its register.

## Goal and scope

Implement #12's missing handler/scope reconstruction and recover genuinely
supported exception-bearing functions. Plain generated-frame unwind already
exists; generating another valid `.pdata` record for a non-EH function is not
completion of this assignment.

The target is native x86-64 PE SEH plus the MSVC C++ EH formats actually present
in the supported fixtures/corpus, including real handler dispatch, filters,
cleanup/unwind and continuations after relocation. Preserve existing host
language semantics without source annotations. C/C++ host fixtures are valid;
this does not add a C/C++ SDK. Rust SDK panic policy remains `panic=abort` unless
separately changed by the user; do not advertise Rust panic-unwind support from
one successful MSVC catch test.

Read #12/#20/#23/#33, D11/D31 and their later superseding decisions, research
section 3, tooling and current `kamy-seh`, PE exception/reference parsing,
linker classification and IR exceptional-effect machinery. Use primary Windows
unwind/SEH specifications and maintained compiler/runtime format references.
The VM-specific phantom-frame research is not permission to introduce a dummy
VM frame or generic catch wrapper for native SSA-lowered code.

## Existing work to preserve

- Actual machine-CFG stack/nonvolatile analysis, plain Version 1/2 unwind cases,
  fixed-frame-base saves, full unscaled FAR offsets and Windows native unwind
  evidence. The old issue's absent XMM-restore claim is historical.
- Concrete frames and frame-backed value locations from 02; symbolic code/data
  identities and final image plan from 01/04; exceptional instruction effects
  and native boundaries from 05/required earlier prerequisites.
- Current fail-closed rejects for unknown/unprovable metadata and the known
  C++ personality/runtime closure kept resident. These guards may become
  obsolete only after their actual cause is implemented and exercised.
- Non-enforcing CFG default, entry/exports/TLS/relocation semantics and the
  supported SDK lifecycle. Do not enable enforcing CFG as an EH workaround.

## Required implementation order

### 1. Inventory precise exception metadata and rejection causes

Replace the umbrella count with meaningful domain classifications, not a
cosmetic rename of `SEHComplex` into many equivalent buckets.

- Identify unwind versions/flags/opcodes, chained records, fragments/funclets,
  language personalities, C scope records and C++ EH payload versions actually
  present. Preserve ownership, shared metadata, aliases and all consumers.
- Distinguish valid unsupported format from malformed/truncated/cyclic metadata,
  incomplete source coverage, unprovable frame state, missing CFG edges and
  unsupported instruction semantics. PE layouts remain in PE-specific crates.
- Parse variable-length/signed encodings, relative bases, embedded pointers and
  function-relative versus image-relative fields according to the format.
  Never reinterpret an unknown handler's payload as a guessed C_SCOPE_TABLE.
- Read the corrected current #23 evidence. Historical `0xc0000409` does not
  prove a /GS or CFG cookie bug; it can be termination after an unhandled C++
  exception. Classify the actual cause through the headless workflow.

### 2. Represent exceptional control and source-to-machine ranges

Handlers cannot be repaired by rebasing a few RVA fields while the optimizer
forgets which operation can throw or which state cleanup observes.

- Carry protected regions, landing targets/funclets, unwind/cleanup states and
  exceptional successors as real shared contracts between lifter, SSA,
  optimizer, frame/location lowering and codegen. Introduce only relationships
  with real producers and consumers, not a disconnected EH metadata sidecar.
- Preserve exceptional reads of locals, object lifetimes, nonvolatile registers,
  frame aliases and values visible to filters/handlers. An exceptional use must
  keep a value alive even when its normal return path never reads it.
- Maintain source-operation to emitted-instruction range relationships through
  block reordering, splitting, expansion, inlining where supported and final
  placement. Scope boundaries are half-open and may not be representable as
  one min/max hull after layout; do not cover unrelated code accidentally.
- Preserve trap/fault ordering and the relevant context at observable operations.
  Memory-backed scratch/helper instructions can themselves fault; do not assign
  them an arbitrary source scope or claim an exception at the wrong logical
  state is equivalent.
- Preserve catch/filter/finally behavior for exceptions at supported call sites
  and synchronous faulting instructions. A source instruction that was protected
  must not escape its handler because its implementation spans new fragments.
- Prevent transformations from moving effectful/throwing work across region
  boundaries without proof. Do not globally disable requested transformations
  on every EH function instead of implementing their state/range contract.

### 3. Reconstruct real native unwind and scope data

- Emit sorted nonoverlapping RUNTIME_FUNCTION ranges and matching real frame/
  save semantics, including multiple generated states, split code, funclets,
  chained relationships and representable unwind versions.
- Support handler flags and C_SCOPE_TABLE begin/end, filter/handler and jump
  continuation relationships. Preserve special sentinel values as such, not
  as symbols that accidentally relocate. Preserve nesting and dispatch order.
- Describe actual saves/restores for GPR/XMM, establisher/frame bases and
  generated large frames. Do not use prologue-only metadata, synthetic saved
  values or an original-entry jump to impersonate correct body unwind.
- Rebuild supported language-specific payloads against final code/data placement
  and frame locations. This includes C++ state/IP maps, try/catch/unwind maps,
  funclet/continuation addresses, parent-frame relationships and handler data
  necessary for actual destructor and catch behavior.
- Implement and verify the MSVC EH3/EH4 variants present in the assigned test
  matrix. Do not cast one to the other's layout or move a personality routine
  while leaving its relative bases and private payload fields stale.
- Guard/cookie-associated personalities such as GS-aware SEH handlers need
  correct saved-cookie/frame relationships. Preserve stack-cookie semantics;
  disabling GS, bypassing the cookie check or keeping cookie-framing functions
  resident does not prove this acceptance.
- Preserve ABI register/context contracts for filter, finally, catch and unwind
  calls, collided/nested unwind and parent-frame access. The regular function
  call ABI is not proof of personality/funclet ABI.
- Rebase every required handler/continuation relationship using symbolic IDs,
  not numeric range scans. Keep old records only when they legitimately describe
  resident code, not as a hidden routing path to original EH entries.
- If existing CET/EH-continuation metadata constrains the rewritten continuations,
  preserve/rebuild that required consistency or fail explicitly. Do not expand
  into optional enforcing module CFG/longjmp/SAFESEH product features merely
  because the vendor advertises them.

### 4. Remove only proven obsolete EH/runtime gates

- Root-cause the known personality/runtime/throw-helper residency constraints.
  Enable movement of the actually supported cases and verify exception search,
  unwind and catch dispatch, not just normal no-throw execution.
- Do not delete the closure guard wholesale, change function names to evade it,
  or shrink the chosen mover set to avoid the original failure.
- Unsupported handler formats or unprovable dynamic frames may still reject
  specifically. Do not call arbitrary C++/SEH fully supported while those limits
  are hidden behind broad generic success or all-EH rejection.
- Keep semantic/CFG/reference/allocation prerequisites separate in diagnostics;
  a pressure problem belongs to the shared backend, not a private EH allocator.

## Required runtime and regression matrix

Build portable self-contained fixtures with Windows execution gated appropriately.
Use actual native dispatch/unwinding, not mocked handler calls or checking only
serialized records. Run protected children with kamy-run.

1. C `__try/__except`: handled and unhandled paths, filter accept/search/
   continue-execution cases where valid, nested regions and multiple handlers.
   Verify side-effect order, exception code and continuation result.
2. `__try/__finally` and supported `__leave`: normal and exceptional cleanup,
   nesting, early exits and abnormal-termination observations. Cleanup must run
   exactly when required, not simply once somewhere before process exit.
3. Exceptions thrown/raised through several moved frames with register and
   stack-resident locals. Include frame-backed intermediates live only to a
   handler, saved nonvolatile GPR/XMM and parent-frame access.
4. Synchronous native faults in assigned protected regions, with controlled
   recovery where defined. Exercise body-range mapping after block changes,
   not only an explicit RaiseException call with a conveniently isolated scope.
5. MSVC C++ throw/catch with supported EH3 and EH4, nested catches/rethrow,
   stack-object destructors, cleanup on normal/exceptional exits and catch
   funclets. Verify observable destructor/state ordering and preserved object
   values, not merely exit zero. Include CFG and GS-enabled variants.
6. Chained/split runtime records and funclets; actual RtlLookupFunctionEntry/
   RtlVirtualUnwind checks at meaningful generated body/epilogue states. Native
   language dispatch tests must supplement virtual-unwind structure checks.
7. Nested/dispatch-during-unwind cases supported by the runtime contract;
   if invalid C++ double-throw must terminate, preserve termination rather than
   suppress the second exception to make a catch test pass.
8. Forced-ASLR EXE and returnable DLL targets, including load/call/unload and
   module/host code interactions. SDK panic=abort still behaves as documented;
   do not catch abort and report it as ordinary successful module initialization.
9. Malformed/truncated/unknown/cyclic metadata yields a contextual parse/error
   or domain reject before corrupt output. Shared scope/handler data must not
   be modified in place in a way that breaks a resident consumer.
10. A stable cohort of previously rejected EH functions now really lowers/moves
    and its throwing path executes. Include the previously problematic throw/
    personality runtime path where its supported metadata is now reconstructed.
    Do not cite a passing file whose relevant functions all remained resident.
11. Existing corpus, transformed supported fixtures, SDK cases and whole-image
    placement still pass. Keep plain-frame unwind and non-EH coverage green.
    Use the maintained in-tree SEH fixtures and the documented external MSVC
    suite where available; do not vendor third-party source or silently treat
    an unavailable external suite as executed.

Use deterministic semantic assertions. A larger `.pdata` table, a renamed reject
or fewer `SEHComplex` counts without exceptional execution is not proof.

## Delivery

Follow the master/extension gates, atomic commits and no-push policy. Update the
existing architecture/status/tooling with exact supported personalities, payload
versions, frame limitations and before/after per-function evidence. Migrate
callers and remove stale comments claiming D31/EH support is wholly absent only
when their replacement is real.

Hand 07 the exceptional edge, source-range and metadata constraints so later
CFG recovery cannot invalidate them. Keep a precise residual list; do not close
#12's umbrella on one C filter fixture while assigned C++/chained cases remain.
