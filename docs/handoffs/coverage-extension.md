# Coverage extension — instructions after the core repair campaign

This is an additive roadmap. It does not modify or supersede the completed
[Prompt 1](01-unified-rebuild.md), the confirmed four-stage order in
[00-master.md](00-master.md), or any active predecessor's contracts. Read the
master's [completion register](00-master.md#completion-register) and each
completed handoff's notice; do not restart accepted work or concurrently edit
an active predecessor's shared types.

Read this file with each new coverage prompt and the master contract. Default
execution order: finish 01 -> 02 -> 03 -> 04, then execute 05 -> 06 -> 07.
These numbers are assignment boundaries, not permission to rebuild predecessor
features. Each agent MUST inspect the implementation actually delivered before
starting. A source location/type mentioned in an old prompt may have moved.

## What is assigned where

| Work | Owner | Do not duplicate |
|---|---|---|
| #15 concrete RSP, frame ownership/high-water marks | [02](02-memory-backed-lowering.md) | One shared frame model, not a second EH/native spill frame |
| #6/#5 applicability: memory-backed state, nonfatal pressure | 02 | User superseded hard zero-spill; protective MBA strength is separate |
| #16 dead dependencies, #13 call precision residuals | 02 | Signature DB, CRT supplement, thunk resolution and inference already exist |
| #9 pinned live-across-call recovery, #10 recursion | 02 | Acceptance is explicit; no separate implementation merely because issues remain open |
| Required SDK semantic/runtime operations | [03](03-rust-sdk-runtime.md) | Mandatory prerequisites for promised std cases, not blanket #11 completion |
| #11 instruction/flag expansion, #26 segments | [05](05-instruction-semantics.md) | Audit and consume prerequisites already delivered by 01–03 |
| #12 handler/scope/exception semantics | [06](06-exception-semantics.md) | Actual-body plain unwind exists; it is not full SEH/C++ EH |
| #14 residual control-flow recovery, overlap with #18/#19 | [07](07-control-flow-residuals.md) | Existing D24 use-def DAG/petgraph VF2 and table-free lowering must remain |
| Backend instruction/copy/traffic quality | [issue #36](https://github.com/mkxto/kamy/issues/36) | Separate from coverage and protective strength; reuse completed optimizations |
| Fantasy #2/#3/#4 and new protective strength | Not assigned | No covert expansion into these features |

## Dependency exceptions: prerequisites, not parallel architectures

Handoff 01 has delivered bounded arithmetic, physical-boundary and native
symbolic-operand prerequisites. Its
[completion notice](01-unified-rebuild.md#completion-notice) and 05's
[inventory requirement](05-instruction-semantics.md#1-inventory-before-changing-instructions)
identify the scope to preserve and subtract from later residuals. Native flag
rejection is containment, not semantic completion. Credit prerequisite work to
its actual predecessor rather than counting it again as newly recovered work.

Prompt 3 explicitly authorizes semantic work required by its std/runtime
acceptance. If it needs an operation listed in 05, implement the proper shared
producer/consumer there, retain its regression and have 05 subtract that work
from its residual matrix. Do not reject the promised SDK program until 05 or
add a private SDK-only implementation.

Likewise 02 owns correct preservation of currently supported flags/native
boundaries and 06 owns exceptional edges, handler states and personality data.
A discovered cross-cutting defect must be repaired by its cause, then recorded
in both acceptance ledgers; do not invent two fixes or two frame conventions.

If a required earlier acceptance genuinely needs an exceptional/control-flow
prerequisite, the earlier integration owner may pull that bounded prerequisite
forward with explicit ownership and evidence. This does not authorize concurrent
agents to rewrite the same lifter/linker or silently reorder the whole campaign.

## Correct the historical issue assumptions

Read each current issue and its comments before editing or closing anything.

- #8 is CLOSED/COMPLETED: NativeInline register operand pinning and write
  reservations landed. Preserve its regression and sound effect handling.
  Its related rflags-reader limitation is not proof all raw native instructions
  are semantically understood.
- #21 is CLOSED/NOT_PLANNED. Recovered moved switches lower table-free; untouched
  switches keep their existing table and targets. Absolute pointer fixups belong
  to #30. Do not revive jump-table patching or per-entry thunk logic.
- `NoThunkSpace` and verbatim-relocation fallback are removed. Old issue wording
  referring to them is historical, never implementation authorization.
- Some BMI/bit-count operations, SSE movement and call signatures already have
  real SSA support. Do not reimplement an instruction family from its issue
  title or assume a whole family works because one mnemonic is implemented.
- SAVE_XMM plain-frame unwind support already exists. #12's old note about an
  absent XMM restore path must be reconciled with the current implementation.
- Earlier RCA diagnoses and counts are not current failure evidence. Historical
  reports of partial fixes must not be asserted as current-tree crashes without
  a current observation. Conversely, the unfixed root cause of a pinned function
  is not repaired merely because keeping it resident makes execution pass.

The user's figures (4,462 RegPressure / 329 CallerFrameAccess, 791 LiftFailure /
462 Unsupported / 1,647 SEHComplex) came from a historical snapshot. The last
pre-campaign documented snapshot was 1,740 / 64 / 557 / 209 / 3,846 respectively,
over 11,202 targets and 23 passing identity corpus members. Neither set is the
new agent's baseline: 01 is already in progress and may change classification.
Record a fresh baseline only when shared edits have settled. Do not run gates,
formatters or batch measurements against another agent's in-flight tree.

## No-bandaid and acceptance rules for the extension

The master contract continues to apply. In particular:

- One symbolic model, shared backend, frame representation and final link plan.
  No byte-copy relocation, guessed constants-as-pointers, compiler/RVA/function
  allowlists, instruction omission or dummy success implementation.
- Safe reject genuinely unsupported semantics/references before output. A reject
  is not completion of a specifically assigned supported acceptance case.
- A native island may be an explicit effectful operation inside SSA lowering,
  but raw passthrough is not semantic SSA coverage. Report that distinction.
- Removing a rejection guard is not a fix. First implement its missing semantics,
  reproduce the original failing path, then remove only the obsolete guard.
- Do not reduce requested transform intensity, split a failing function into
  easier fixtures, change input flags/goldens or drop target functions to make
  counts improve.
- Preserve original ISA/feature requirements and OS context. No synthesized
  undocumented XMM/GPR interchange, unconditional new CPU feature, fast-math
  relaxation or plain load/store replacement for an atomic operation.
- Permanent tests must be deterministic, portable and exercise consumer-visible
  behavior. Windows/feature-dependent native oracles must be gated appropriately;
  no dependency on a developer's System32 paths, external files or CPU features
  absent from the declared test environment.
- The corpus identity gate, transformed fixtures and structural/runtime evidence
  are complementary. Run actual EXE/DLL outputs with kamy-run, force ASLR and
  exercise native Windows unwinding where relevant. Follow corpus/bisect/dump
  triage when a miscompile is exposed; never use x64dbg as the batch oracle.
- Distinguish instruction semantic coverage, native-island coverage, eligibility,
  reference completeness, frame/allocation success, real transforms and final
  execution. A file that passes with its problematic functions resident is not
  evidence those functions now work lowered.
- Use a stable function cohort and before/after per-function transitions. Identify
  changed discovery boundaries/population rather than treating a denominator
  change as recovered coverage. Explain genuine remaining rejects.

Every prompt requires the repository's fmt/clippy/workspace build/test gates
and its specified smoke matrix after integration; no worker runs them mid-flight.
Commit green milestones atomically, never push. Update existing status/tooling/
decision docs with exercised facts, not a new drifting implementation comparison.
Only close issue acceptance actually satisfied. Unimplemented ISA variants or
EH formats must have explicit residual rows; never mark their whole umbrella
complete because one easy fixture passed.

Each numbered handoff MUST update its own completion notice and the master's
register under the [completion contract](00-master.md#completion-notices).
Record issue work by satisfied subset, evidence, residual owner and successor
contract; an accepted milestone does not imply its umbrella issues may close.

These files are future implementation assignments, not claims that the listed
semantics or EH/control-flow support have already landed.
