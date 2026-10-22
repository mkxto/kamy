# Prompt 7 — Control-flow recovery residuals and integrated coverage

Read `docs/handoffs/coverage-extension.md`, `00-master.md` and the actual
completed implementations. Default execution follows 01-06. Reuse the unified
symbol/reference graph, frame-backed lowering, semantic operations, exceptional
edges and one final layout. This is #14's residual correctness/coverage work,
not a second disassembler, a new obfuscating dispatcher or a jump-table patcher.

## Goal and issue boundaries

Recover provable indirect/static dispatch and improve function/block recovery
where current `BadIndirectBranch`, `ResolvableIndirect` or `LiftFailure` hides
valid supported code. Preserve sound rejection for genuinely unprovable flow.

Read #14/#18/#19/#21 and current discovery/recovery/reference/lifter code. #21
is CLOSED/NOT_PLANNED: it incorrectly bundled switch-table patching with absolute
relocation rebasing. Recovered rewritten switches lower table-free; untouched
switches retain their existing table and unmoved targets. Absolute fixups belong
to #30. `NoThunkSpace` is removed, not a residual to reintroduce.

#9 and #10 belong to 02 and may already be complete. Check their delivered call/
recursion cases when new flow exposes them; do not implement a private copy/
recursion fallback or call them unfinished solely because GitHub remains open.
#8 is fixed; retain its operand/effect contracts and regressions.

## Required work

### 1. Classify by actual failure before increasing reachability

- Inspect current discovered functions, ownership, seeds, blocks and exit kinds.
  Distinguish unknown flow from invalid instructions, unmodeled semantics,
  noreturn/exception exits, data-in-code, tail calls, imports/forwarders and
  incomplete source boundaries. Avoid one generic LiftFailure conclusion.
- Use matching PDB/symbol, unwind, export/entry and compiler-authored metadata
  where available; preserve the no-PDB conservative path. Do not make symbols
  mandatory for arbitrary host processing or accept a mismatched PDB.
- Preserve exact per-function incoming/outgoing references and uncertainty.
  More decoded bytes are not automatically more real functions or coverage.
- Keep analysis deterministic and bounded. A malicious or malformed dispatch
  cannot request unbounded graph growth, table allocation or recursive decoding.
- Establish stable-cohort baseline transitions before and after each category.
  Discovery changes require source-identity accounting, not misleading changed-
  denominator percentages.

### 2. Resolve genuinely known indirect control transfers

- Recover immutable pointer-slot branches/tail calls from authoritative loader/
  relocation/reference data or proven value propagation. Distinguish imports,
  forwarders, ordinary calls, tail transfers and intrafunction edges.
- Prove slot immutability at the relevant program point before replacing an
  indirect transfer with a direct one. An IAT or writable callback slot is not
  immutable merely because the input file contains one pointer value.
- Register/stack/dataflow target resolution must track actual aliases, writes,
  joins, table bounds, signed extension and arithmetic widths. Unknown target
  components remain uncertainty, not a guessed finite set.
- Distinguish direct-ification, finite multi-target dispatch and unresolved
  indirect edges. Preserve dynamic/external targets and ABI/CET semantics;
  do not insert a default edge to a convenient known function or silently drop
  rare cases. An indirect call is not a terminal indirect jump.
- Use the shared symbolic references for final target binding. Do not snapshot
  a computed target VA before compaction or emit an old-address trampoline.
- Newly recovered call/tail boundaries must keep correct argument/return/clobber
  and exception contracts; CFG success alone does not prove a safe call ABI.

### 3. Extend the existing D24 switch recovery, not its design

The settled engine is the use-def DAG plus petgraph VF2 and proven value/bounds
analysis. Keep it; no replacing it with a permissive byte-pattern shortcut or
"just scan dwords that look like RVAs."

- Audit existing layers and already handled idioms before adding residual ones.
  Include register copies/renames, width extensions, image/table-base offsets,
  signed relative entries, duplicated case destinations and default bounds.
- Support assigned dense/sparse/two-level index/value dispatch forms as proven
  in the corpus or deterministic fixtures. Associate selector values with the
  correct successors, preserving duplicate entries and fallthrough semantics.
- Validate table width, extent, initialized ownership, index transformation,
  in-range targets and complete default behavior. An apparent sequence of
  executable addresses is not proof of a switch or of a complete bound.
- Materialize recovered case bodies/edges in the shared CFG. Rewritten bodies
  must lower table-free through the same semantic/backend path; do not move
  raw dispatch bytes and retarget a surviving table as a convenient third state.
- An untouched source keeps the table and its necessary targets resident.
  A reference from a resident switch may pin movers legitimately; do not delete
  that constraint just to permit another function's movement.
- Do not promise CD's computed-pad/continuation obfuscation. This assignment
  recovers and preserves control semantics; protective CFF/dispatcher strength
  remains separate.

### 4. Repair recovery boundaries and terminal semantics

- Propagate proved noreturn behavior from actual signatures, trap instructions,
  supported local analysis and exceptional exits. A normal function with one
  observed terminating path is not globally noreturn.
- Do not decode past a definite trap/noreturn into data and merge unrelated
  functions. Conversely, do not truncate a valid tail/cold block merely because
  a heuristic nearby seed or broad metadata fragment suggests a boundary.
- Distinguish data-in-code, padding, literal pools, embedded tables and real
  instructions using ownership/reference evidence. Do not reinterpret alignment
  CC bytes as live code or delete unknown bytes merely to shrink a function.
- Preserve shared tails, cold fragments, funclets, jump-to-shared-code and source
  identity across blocks. Handle ownership conflicts explicitly instead of
  double-moving overlapping ranges or assigning arbitrary ownership by order.
- Reconcile ordinary CFG and 06's protected regions/exceptional successors.
  New recovery cannot bypass cleanup/handler state, invent normal fallthrough
  from an exception exit or erase a funclet's parent relationship.
- Calls and recursion exposed by new reachability consume 02's frame-backed
  backend. Remove an obsolete rejection only when the actual recovered code
  path is supported, not because a classification label changed.

### 5. Keep expanded coverage compatible with both layout modes

- Feed only resolved symbolic targets/ownership and explicit uncertainty into
  the same link plan. Selective output may preserve unresolved residents.
- Whole-image compaction must fail explicitly if any affected flow/reference
  remains unprovable. Do not relabel a partial selective output as globally
  compacted, guess a branch or add an original-entry stub to satisfy the mode.
- Displacements, table-free case edges, taken addresses, unwind/scope ranges,
  exports and module/runtime references must bind at final placement. Existing
  translation mechanisms are valid only for their actual rewritten consumers.
- Do not attribute semantically unsupported instructions, frame-state limits,
  unknown EH payloads or true resource limits to a generic control-flow reject.
  Preserve their independent gates and diagnostics.

## Required acceptance matrix

Use portable deterministic fixtures with real branch/side-effect oracles and
actual kamy-run execution. Tests must prove complete behavior, not just that a
recovered target set is nonempty or a block count increased.

1. Proven immutable in-image slot tail transfer/call recovers and executes after
   relocation and forced ASLR. A writable slot modified before use must retain
   correct indirect behavior; prove the implementation did not direct-ify it
   from the file's initial value.
2. Finite multi-target dispatch covers every selector value plus default/out-of-
   range paths. External/unknown target variants remain explicit uncertainty;
   no target-set truncation or default-to-first-entry fallback.
3. Dense and sparse/two-level switch fixtures exercise selector transforms,
   register renames, signed relative entries, duplicate destinations,
   fallthrough and defaults. Recovered rewritten dispatch is really table-free
   and produces the original results for the whole bounded input domain.
4. Untouched switch/table behavior remains valid with resident targets; no table
   patching or hidden thunk resurrects the closed #21 design. New lowering
   consumes the existing DAG/VF2 engine, not an unrelated pattern recognizer.
5. Local noreturn, trap, normal-return and exceptional-exit fixtures recover the
   right successors without dead-data overdecode. Include cold/shared tails,
   real metadata fragments and deliberate code/data ambiguity negative cases.
6. Recovered loops/calls include pinned live-across-call values and supported
   self-recursion; existing frame-backed/phi/copy correctness remains intact.
   Observe actual state/results, not only the absence of RegisterPressure.
7. Recovered EH-bearing paths preserve exceptional edges, scope state and
   cleanup behavior from 06. Verify both normal and throwing paths under final
   placement; a no-throw execution does not prove CFG/EH integration.
8. Overlapping ownership, invalid targets, malformed bounds, cyclic analysis and
   unprovable dispatch fail/reject specifically and within bounded resources.
   A larger code range or a dropped problematic function is not recovered
   coverage.
9. Existing identity corpus remains green, supported transformed/module cases
   still execute, and stable-cohort CF-caused rejection transitions are measured.
   Test selective and completeness-proven whole-image layouts and report their
   eligibility separately. Do not claim every BadIndirectBranch is recoverable.

## Delivery and final coverage ledger

Run all master/extension gates after integration, use headless bisect/dump for
exposed miscompiles, update existing docs with exercised evidence, commit green
milestones atomically and never push. No blanket allowlists, altered goldens,
verbatim relocation or hidden reduction of requested protection.

The final ledger must separately reconcile:

- Allocation/frame: #15/#6/#5 applicability, #16/#13 residuals, #9/#10.
- Instruction semantics and faithful native islands: #11/#26, preserving #8.
- Exception/frame/scope/personality support: #12/#20 and residual #23 causes.
- Control-flow/reference completeness: #14/#18/#19; #21 remains not planned.
- Code quality #36 and protective strength/fantasy #2/#3/#4 remain separate.

For every remaining rejection, state the actual unsatisfied contract and a
representative witness. Do not close umbrella issues or claim full CD parity
from a passing limited corpus. The purpose is real supported-code expansion
without weakening the native rewriting model.
