# Prompt 2 — Concrete frames and CD-aligned memory-backed lowering

Implement this assignment after Prompt 1. Read `docs/handoffs/00-master.md` and
`01-unified-rebuild.md`, then inspect the actual preceding implementation and
its evidence. Do not recreate its symbolic model or link plan.

## Completion notice

**Status: Incomplete / Reopened 2026-10-22; repairs evidenced 2026-10-23.**
Acceptance of implementation `278f5ef81dd096e8325c06bd02ba7c88b84b0646`
(`Lower SSA through concrete memory-backed frames`), published at `d1c70e1`,
remains withdrawn. Policy `5ef9b46` (D40) remains binding: one backend, concrete
memory-backed frames, bounded scratch, explicit flags, one rebuild and actual-body
unwind. Pressure rejection and transform-intensity retries MUST NOT return.

All seven [review findings](../STATUS.md#post-acceptance-review--2026-10-22)
now have a repair or scoped disproof:

- **#37 fixed** (`d87d989`): finite conditional/phi/copy provenance and final
  logical-frame mapping, including delayed dominating constants and separated
  E−8/E+8 alternatives; real native identity/MBA and shared-DAG witnesses retained.
- **#38 scoped disproof** (`19bffa6`): actual compiled, parsed and resolved ordinary
  Rust 1.95 / LLVM 22.1.2 CCC/FastCC contracts, including a genuine 24-byte SRet,
  disprove the current supported-producer concern. This is not fabricated
  RBX/XMM6 metadata or proof for arbitrary LLVM/custom ABIs; preservation-override
  attributes remain outside the evidence.
- **#39 fixed** (`b6f94b2`): per-analysis scalar success/failure/cycle caching.
- **#40 fixed** (`c0bfb28`): candidate-free skip and compact petgraph dominators;
  linear storage, not a linear-time claim (worst-case time remains O(V²)).
- **#41 fixed** (`32aaeb4`): bounded simultaneous phi scheduling with one cycle slot.
- **#42 fixed** (`3a68d4c`): saves follow actual physical writes, not read-only entry capture;
  registered native Windows unwind checks preserve full 128-bit XMM state.
- **#43 fixed** (`57eb3b1`): one global pins map and private four-value local allocation.

**Formal H2 acceptance is still blocked:** the original 23-member population at
locked corpus revision `d9bc70d9970d3e1988203acd3415b103bcb62197` is unavailable.
The available subset is not a replacement. The original `dll_strutil` remains
quarantined/user-skipped, not restored, rebuilt, reblessed or counted PASS.
No original/golden/security policy was changed. H3 MUST wait; this notice and
the [master register](00-master.md#completion-register) track handoff acceptance,
not remote or umbrella issue closure.

| Issue scope | Delivered scope and disposition | Residual owner |
|---|---|---|
| #15 | Concrete homes/coordinates and bounded resources; finite provenance repaired | H2 corpus reacceptance; truly unproved/dynamic frames remain explicit |
| #6 | D40 memory-home cutover plus bounded DAG/CFG/phi work and one global pins map | H2 reacceptance; no return to zero-spill scheduling |
| #5 applicability | Requested supported MBA intensity retained in fresh witnesses | No pressure-driven reduction; stronger/nonlinear protection stays separate |
| #9 | After-definition captures/homes preserved; actual-write saves and supported call contracts evidenced | Arbitrary custom ABI/preservation overrides are not established |
| #10 | Historical caller-frame/recursion recovery retained; finite selected-frame addressing repaired | Truly unproved frame forms remain explicit |
| #13 | Partial: metadata/CRT/import-thunk/inference retained; actual authored ABI and conservative unknown calls preserved | Broader signature precision is not declared complete |
| #16 | Partial: successor-aware per-bit dead-flag dependencies removed only when proved dead | H5 owns unmodeled flags and variable-count carry semantics |
| #23 | Historical 23-member success retained as history; available population reverified, original full gate unavailable | H2 original corpus gate; H5/H6 retain native termination/EH residuals, including the two historical INT29 losses |
| #8 | Physical native pins/effects and bit-string widths/offsets preserved | H5 owns FS/GS and unknown native classes |
| #17 | Bounded prerequisite: one-plan frame/probe/helper and typed metadata references retained | H4 global compaction and later reference residuals remain |
| #20 | Actual-body saves/probes/unwind retained; registered Windows read/partial/write-state proof refreshed | H6 retains handler/scope/personality reconstruction |
| #30 | Bounded prerequisite: validated BaseReloc scalar ownership preserves records and field rebasing/rebuild | HIGHLOW/opaque-reference limits remain conservative; H4 owns global layout |
| #32 | Intact combined Rust callback executes identity and full MBA through the shared backend | H3 owns compiled startup, ordinary imports, std/runtime/TLS and lifecycle |

### Verification and remaining limits

The [current H2 STATUS evidence](../STATUS.md#current-h2-repair-evidence--2026-10-23)
records current commands, versions, source/output identities, exact PC/ABI
annotations, native oracles, work/allocation scaling and stable-population
transitions separately from historical results. Fresh workspace gates, full
SDK rebuild/runtime, the explicitly ignored genuine producer test and all
available corpus members passed; numerical detail belongs there. Identity
lowering is not actual MBA: the exact normalized select ledger has no eligible
arithmetic, while nearby witnesses and the standalone frame SDK genuinely
transform at requested intensity. The intact combined callback, depth-64
recursion, large guard frame and independent Windows native unwind proofs
remain load-bearing, not substitutes for the missing full corpus.

Manual in-tree CLI/IR/protection/rejection work and exact native byte/PC, frame,
ABI/call/result, save, phi/flag and unwind inspection were exercised under the
user's explicit **Kamy-only** campaign authorization. No IDA/x64dbg was run or
is claimed. The semantic/manual proof obligations remain; any genuinely
debugger-dependent residual must stay blocked. None was established here.

Dynamic/unproved frames, unsupported native effects, FS/GS, variable-count carry
and unchanged semantic/reference rejections remain explicit. The checked frame
bound remains 16 MiB. GuardCF repair is not CFG enforcement; plain-frame unwind
is not arbitrary EH. H3–H7, stronger protection and broader output optimization
retain their scopes; no std/startup or whole-image compaction completion is claimed.

### Successor contract

After H2 reacceptance, H3 MUST reuse the [concrete code-generation contract](../architecture.md#81-code-generation):
`FrameAnalysis`, `ConcreteFrame`, `FrameHome`, `FrameSave` and `RegAllocation`;
`allocate_registers(func, rsp_pinned, reg_pins)` and
`select_instructions(func, alloc)`; actual `frame.saves` rather than obsolete
save-vector helpers. `FrameHome` is the memory-home representation, not a second
`MemoryHome` API. Keep one authoritative global pins map and private bounded
four-value instruction-local allocation; no duplicate map or adapter. The
scratch/ABI contract is seven ordinary GPRs and four XMMs, explicit native/ABI
boundary pins, after-definition result capture, explicit flag homes and
memory-phi/cycle scratch. Preserve original LOW storage, generated HIGH
homes/saves, entry-relative incoming coordinates and original outgoing storage;
the known outgoing minimum is not a guessed argument extent.

`construct_ssa(&mut LiftResult) -> Result<(), RejectionReason>` is mandatory
before transforms, including identity. Reuse
`build_callconv(&PeFile, &Module) -> anyhow::Result<MapCallConv>`, exact
`FnSignature`/`AbiValue` contracts and conservative unknown-host calls. Actual
machine-CFG unwind consumes actual saves/probes/epilogues. Reuse
`MetadataReferences { references, classified_ranges }`: validated scalar ranges
exclude speculative scans, not real reference enumeration/rebinding. Preserve
`SymbolId`, `Reference`/`SymbolicExpression`/`LinkField`, `SelectedInstructions`,
`AuthoredSource` and the single `kamy_link::protect` plan. KAMYMOD v2,
`kamy-debug-map,2` and `kamy-link-report` v1 remain unchanged; allocation reporting
is additive. See [architecture successor contracts](../architecture.md#86-contracts-consumed-by-the-next-handoffs).

Portable fixtures H3 MUST retain and reuse:
[standalone frame host](../../tests/sdk-rebuild/hosts/frame.rs),
[frame runner](../../tests/sdk-rebuild/src/frame.rs),
[native unwind oracle](../../tests/sdk-rebuild/src/native.rs),
[shared native probe helper](../../tests/sdk-rebuild/src/native_probe.rs),
[probe support](../../tests/sdk-rebuild/src/probe.rs), intact combined callback
[original](../../tests/sdk-rebuild/plugins/pressure/original.rs) and
[protected source](../../tests/sdk-rebuild/plugins/pressure/lib.rs), codegen
[memory frames](../../crates/kamy-codegen/tests/memory_frames.rs) and
[frame coordinates](../../crates/kamy-codegen/tests/frame_coordinates.rs), link
[memory frames](../../crates/kamy-link/tests/memory_frames.rs),
[call aliases](../../crates/kamy-link/tests/frame_call_alias.rs) and
[guard calls](../../crates/kamy-link/tests/guard_calls.rs). These use the existing
specialized DLL producer, not external temporary executable dependencies.


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
7. All previously passing identity corpus members remain passing, including
   the original 23-member locked population; an available subset does not waive
   that gate. Recover measurable pressure/caller-frame cases over a stable
   target population; report genuine remaining semantic/reference limits and
   additions/removals separately. Do not invent unmeasured percentages.
8. Supported requested MBA intensity/order is preserved on recovered functions;
   expose actual memory-backed allocation, frame size and resource diagnostics
   without using a warning to excuse reduced protection.
9. Dynamic/unprovable frame or unsupported-semantic fixtures fail specifically
   and deterministically without emitting partially protected output.
10. All seven [post-acceptance review findings](../STATUS.md#post-acceptance-review--2026-10-22)
    MUST be fixed or reproducibly disproved. Commit deterministic portable
    regressions, with Windows execution appropriately gated; supplemental local
    artifacts MUST NOT become prerequisites. Keep every original gate above.
    No blanket rejection, witness special case or reduced requested MBA intensity
    may replace correct lowering of the supported finite select counterexample.
11. Preserve finite frame-pointer provenance through CMOV/select, subsequent
    arithmetic and phi/select/copy composition. Execute the ledger's six-argument
    witness for constant and variable conditions in identity and requested MBA;
    both branches MUST return the original arg5/arg6 values. Check original LOW,
    generated HIGH, incoming/home and outgoing coordinates, flags, mixed GPR/XMM
    homes, phi cycles and after-definition call results against native behavior.
12. For the call-contract finding, establish reachability with a real accepted ABI
    producer/consumer, or document reproducible producer evidence disproving it.
    For accepted RBX/XMM6+ result/clobber cases, correctly unwind successive calls,
    interior body PCs and epilogues, retaining real saves and standard Win64
    behavior. Use Windows `RtlLookupFunctionEntry` / `RtlVirtualUnwind` against
    exact rebuilt outputs under forced ASLR; a static claim or an assumed fixed
    Win64 mask is not verification of accepted cases. Read-only pins MUST avoid
    unnecessary saves while actual native/call/output writes retain required saves.
13. Demonstrate bounded scalar-DAG, CFG/dominator and phi-copy analysis with
    actual size/work/allocation scaling evidence, not claimed timings. Cover
    shared successes/failures, cycles, overflow/resource boundaries, candidate-free
    acyclic CFGs, reducible/irreducible loops, wide/reverse chains and copy cycles.
    Keep facts fresh after transforms and preserve sound range/rejection semantics;
    do not hide work with arbitrary threshold rejection or flaky timing assertions.
    Remove the duplicate global pin map and migrate consumers without adapters.
14. Before reacceptance, manually exercise the in-tree triage, IR, protection and
    explain-reject tooling for the relevant witnesses. Inspect source/SSA,
    transforms and allocation/homes with `kamy dump`; inspect exact emitted
    native bytes/PCs using old/new symbol and RVA maps for the rebuilt identity
    and requested MBA outputs. Annotate frame/address calculations, ABI and
    analysis adjustments, calls/results, saves, phi/flag transfers and unwind
    states. Execute those same outputs and compare observable values and caller
    state, including independent forced-ASLR Windows unwind probes.
    The user's explicit Kamy-only authorization supersedes the literal IDA tool
    requirement for this campaign, not these semantic/manual evidence duties.
    No IDA/x64dbg execution may be claimed; any genuinely debugger-dependent
    residual stays blocked. Screenshots, pretty decompilation and tests alone
    are NOT correctness proof.
    Follow [the in-tree tooling contract](../tooling.md#miscompile-hunt-workflow):
    `kamy bisect` with an output oracle when exit status alone cannot distinguish
    failure, `kamy dump` at `lift`, `ssa`, `optimize`, `regalloc` and `native`,
    `kamy protect` with identity and the requested MBA profile plus debug-map/link
    reports, and `kamy explain-reject` for applicable negative fixtures. Use
    authored module identities rather than inventing host RVAs for module code.
15. Record before/after evidence in the existing STATUS/handoff ledger: versions
    of tools actually used, implementation commits, build identity, input/output
    identities or hashes, exact commands/results, old/new symbol/RVA maps,
    annotated PC/ABI/analysis observations, native oracles and scaling evidence.
    Explicitly distinguish observed results, static findings, unavailable tools
    and unresolved gates. All original gates require fresh repair evidence;
    earlier successful campaigns cannot substitute for manual CLI/native-runtime
    reacceptance or the original locked corpus population.

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
