# Prompt 2 — Concrete frames and CD-aligned memory-backed lowering

Implement this assignment after Prompt 1. Read `docs/handoffs/00-master.md` and
`01-unified-rebuild.md`, then inspect the actual preceding implementation and
its evidence. Do not recreate its symbolic model or link plan.

## Completion notice

**Status: Pending; no completion accepted.** Assigned issue scopes are
#15/#6/#5 applicability, #16/#13 residuals and #9/#10, preserving corrected #23
behavior. These are assignments, not claims of work performed. On completion,
replace this notice with the issue-by-issue work/evidence/residual ledger,
accepted commits and successor contracts required by the master's
[completion contract](00-master.md#completion-notices), and update its register.

## Goal and explicit policy change

Establish concrete frame reconstruction and memory-backed intermediate state
with a bounded scratch-register working set, as described in
`docs/code_defender.md`'s register model. Pressure must not reject otherwise
supported functions or force a reduction of the requested transformation.

This is not merely a late spill retry after the old intensity ladder. It is a
correctness-first lowering model with register-resident optimization permitted
when it preserves the pressure bound. Avoid unnecessary stores/copies for dead
values and rematerializable pure literals; do not interpret memory-backed as
permission to emit avoidable work indiscriminately.

D40 already records the user's replacement of D5's hard zero-spill policy.
Consume that settled decision; reconcile remaining obsolete rules/comments as
the backend cuts over rather than reopening the policy. Reconcile #15/#6/#5:
#6 describes preserving zero-spill through serial scheduling, which is not the
agreed default. Stronger nonlinear MBA remains out of scope.

## Preserve and investigate before changing

Read #15, #6, #5, #16, #13, #9, #10 and corrected #23 history. Inspect the real
allocator/lifter/isel/unwind/shared-frame callers through language-server
references. Starting areas include:

- `crates/kamy-codegen/src/{regalloc,isel,lib}.rs`.
- `crates/kamy-lift/src/{lib,ssa}.rs` and operand/state/call lowering.
- `crates/kamy-core/src/ir`, including call signatures and native effects.
- `crates/kamy-analysis/src/sig.rs`, existing liveness/optimization consumers.
- `crates/kamy-link/src/lib.rs` and the shared backend left by Prompt 1.
- `crates/kamy-seh/src/unwind.rs` and its real machine-CFG state analysis.

Existing GPR and XMM callee-saved pools, Win32metadata/CRT signatures, import
thunk resolution, callee-side inference, SSA call-argument pin transfer,
parallel-copy logic and actual-body unwind are working mechanisms. Extend
rather than reimplement them. Do not assume GPRs and XMMs are interchangeable.

Read the [completed H1 notice](01-unified-rebuild.md#completion-notice) and its
accepted `feaffd8` evidence in [STATUS.md](../STATUS.md), then measure the current
tree after any intervening work. Keep that fresh baseline distinct from H1's
historical comparison. Report recovered functions, rejection-class migrations
and previously lowered functions that regress separately; a pressure reject
becoming `CallerFrameAccess` is not recovered coverage.

## Required implementation order

### 1. Establish one concrete frame model

Use a shared format-agnostic frame representation with real lifter, lowering,
codegen and unwind consumers. Reuse contracts introduced by Prompt 1.

- Track entry RSP and statically known RSP deltas through the CFG, copies,
  register aliases and joins. Observe high-water marks at calls and native
  boundaries; do not infer frame size from the last `sub rsp` instruction.
- Distinguish return-address storage, incoming stack arguments, caller-owned
  shadow/home slots, original local storage, outgoing call arguments/shadow
  area, nonvolatile saves, intermediate/spill slots and any copy scratch slot.
- Preserve pointers materialized into the original frame and their aliases
  across calls/blocks. Adding a new frame zone must not silently change the
  addressed original object or overwrite a saved nonvolatile.
- Reconcile different path states explicitly. Dynamic/unprovable frames can
  remain a specific semantic limitation; do not pretend concrete-RSP analysis
  proved them. Do not use a catch-all `RegisterPressure` reject for them.
- Do not double the original frame in recursion. Remove the old caller-frame
  and self-recursion gates only after their causes are repaired and proven.
- Maintain Win64 call alignment, return semantics, shadow space, stack arguments
  beyond four registers, tail calls, saved GPR/XMM offsets and partial-register
  widths. Windows x64 has no general-purpose red zone.
- Handle large-frame stack probing/guard pages and all resulting references
  through the real unified linker. A large stack allocation must not skip
  required probes merely to avoid introducing a helper/import.
- Define representable frame/resource bounds. Real overflow or resource limits
  must fail with their actual cause; "pressure never fatal" is not a claim of
  physically infinite memory or unchecked frame sizes.

### 2. Lower intermediate state to bounded working sets

Implement a real representation and its producers/consumers, not a table that
only records hypothetical spill slots.

- Assign addressable frame-backed homes where needed for intermediate values.
  Preserve widths/alignment, classes, lifetimes, aliasing and definedness.
- Lower operations as bounded load/compute/store working sets, respecting
  implicit/fixed registers, variable shifts, multiply/divide constraints,
  calls, native instructions and actual clobbers.
- Represent and preserve condition/flag state explicitly across definitions,
  uses and clobbers. Memory-backed flags are semantic state, not a blanket
  push/pop of architectural flags without modeling the effects. Preserve
  BoolNot's 0/1 invariant and all currently supported flag behavior.
- Calls must not destroy live intermediate state. Place argument/return values
  according to their actual contract; save produced results after their
  definition, not before it. Use Prompt 1's authored ABI provenance.
- Implement correct mixed register/memory phi destruction, critical-edge
  transfers and parallel-copy cycle resolution. A full scratch register set
  must not make a copy cycle intrinsically unlowerable when a frame scratch
  slot can implement it correctly.
- Preserve NativeInline read/write/pin/flag/memory effects. Do not suppress
  an unmodeled effect or treat opaque bytes as proof of arbitrary semantics.
- Remove pressure-based transform-intensity retries and pressure-only rejects
  from the supported path once the replacement is proven. Do not leave the
  old backend as an alternate fallback or claim success after an identity
  retry when a nonzero transform was requested.
- Use the same backend for host code, SDK callbacks, loader code and dependency
  functions. No special allocator for plugins or a sample-sized register pool.

Register caching, slot reuse and pressure-aware evaluation ordering are valid
optimizations only after correctness. They must not weaken the finite scratch
bound or alter requested protection. Do not use guessed liveness to reduce
memory traffic.

### 3. Integrate real unwind semantics

- Generate unwind for the actual emitted frame, saves/restores and CFG states.
  Keep fixed-frame-base offsets and correct large/FAR encodings.
- Reuse actual-body analysis and the unified Exception directory. No fake
  prologue-only metadata or entry shim standing in for correct body unwind.
- Prove call, branch, epilogue and empty-frame states. Unwinding through a large
  intermediate frame must recover the caller and saved GPR/XMM state.
- Full C++ EH/scope/handler reconstruction remains a separate track. Preserve
  safe rejection of those functions; do not advertise plain frame unwind as
  general language-exception support.

### 4. Recover coverage using existing complements, not duplicated work

- Inspect #13's existing DB, precision and fallback behavior. Extend only real
  residual signature gaps justified by metadata; do not undercount arguments
  to make allocation fit or assume all unknown returns are integer RAX.
- Implement or complete #16 dead-dependency analysis where a real boundary
  proves a value/flag is overwritten before use. Preserve partial flag writes,
  memory effects, native reads and uses on every CFG successor.
- Address #9's supported volatile-pinned live-across-call cases with correct
  after-definition transfers/memory homes, preserving the previous ABI pin fix.
- Address #10's supported self-recursion and the actual caller-frame-offset
  problem through the new frame model. Do not just delete their rejects.
- Keep reference completeness and semantic eligibility independent from
  allocation coverage. Do not rename rejects or remove targets to inflate
  the improvement.

## Required acceptance matrix

Use deterministic portable fixtures plus actual headless execution. Retain
before/after witnesses, not only tests that assert new internal structures.

1. The original combined SDK bounds-check/counter callback lowers and executes
   intact. It reads both init-table bounds, checks the expected span, updates
   host-visible state through an authored image-base expression, and returns
   success/nonzero appropriately. Do not split checks/counter into separate
   callbacks, remove branches or lower its requested intensity to make it fit.
   Remove `CaseOutcome::ExpectedPressureLimitation` and the diagnostic-string
   matching allowance from `tests/sdk-rebuild/src/main.rs`, migrating all its
   consumers without a compatibility branch. Pressure rejection, skipped witness
   execution or pressure-driven reduction of requested intensity MUST fail this
   acceptance. The full harness MUST NOT report success without executing the
   witness. H1 already executed this case successfully; preserve that regression
   while proving the general memory-backed guarantee.
2. Supported high-pressure GPR and XMM cases exceed the old register budget and
   execute correctly across blocks, loops, joins, calls and native boundaries.
   Include multiple concurrently live values and copy cycles, not only many
   immediately dead constants.
3. Incoming stack arguments and shadow/home accesses retain their real values
   after generated frame construction. Include functions with ordinary locals,
   address-taken stack storage, callee-saved use and calls with more than four
   arguments, plus mixed argument/return classes supported by the ABI model.
4. Self-recursive supported fixtures reach a meaningful tested depth without
   frame duplication or corrupted unwind. Pinned values produced by calls and
   live across later calls retain their value.
5. Large frames exercise stack probing/guard-page behavior on Windows and
   recover correct nonvolatile GPR/XMM state with `RtlLookupFunctionEntry` and
   `RtlVirtualUnwind`. Test supported interior body and epilogue states.
6. Flags/partial-register behavior survives arithmetic, compound branches,
   native/call clobbers and phi transfers. No ambient RFLAGS assumption or
   accidentally preserved scratch register may carry the oracle.
7. All previously passing identity corpus members remain passing. Recover
   measurable pressure/caller-frame cases over a stable target population;
   report genuine remaining semantic/reference limits separately. Exact
   percentages are not invented before measuring the new baseline.
8. Supported requested MBA intensity/order is preserved on recovered functions;
   expose actual memory-backed allocation, frame size and resource diagnostics
   without using a warning to excuse reduced protection.
9. Dynamic/unprovable frame or unsupported-semantic fixtures fail specifically
   and deterministically without emitting partially protected output.

The corpus cannot by itself prove this backend: it normally runs identity.
Exercise transformed fixtures and real module outputs. Keep golden behavior
unchanged, use the triage workflow for exposed miscompiles, and fix root causes
instead of constraining the witnesses.

## Handoff

Run all gates from the master, document actual before/after transitions, commit
green milestones atomically and never push. Migrate all affected callers/tests,
IR/frame docs and diagrams in the same cutover; remove obsolete no-spill rules,
pressure ladder paths and stale comments.

Hand Prompt 3 the real frame, memory-home, scratch/ABI, call and unwind APIs.
Do not promise arbitrary std/ISA/EH coverage merely because pressure is now
nonfatal. Do not add stronger MBA or unrelated protection passes in this prompt.
