# Prompt 5 — Instruction, flag and segment semantic coverage

Read `docs/handoffs/coverage-extension.md` and `00-master.md` first. Execute
against the completed core campaign by default; honor prerequisite work already
delivered by 01–03 and read their completion notices. Do not modify an active
predecessor's contracts or recreate its symbolic/frame/allocation machinery.

## Completion notice

**Status: Pending; no completion accepted.** Assigned issue scopes are #11/#26;
#8's completed operand fix and corrected #23 behavior MUST be preserved. These
are assignments, not claims of work performed. On completion, replace this notice
with the issue-by-issue work/evidence/residual ledger, accepted commits and
successor contracts required by the master's
[completion contract](00-master.md#completion-notices), and update its register.

## Goal and ownership

Deliver the remaining #11 instruction-semantic expansion and #26 fs/gs path.
Preserve the CLOSED #8 NativeInline fix. This assignment owns missing operation
semantics and effect contracts, not stronger obfuscation, another allocator,
full language EH, or speculative CFG recovery.

Read #11/#26/#8, relevant #23 corrected RCA, the current lifter/SSA/IR/optimizer/
selector/native effects and the architectural specifications for each operation.
Use maintained decoder metadata and primary Intel/AMD/Windows references; do not
use mnemonic familiarity or an emulator as the sole semantic specification.

The current named families include SSE/AVX arithmetic/conversions/shuffle/pack,
x87, string/REP, atomics/LOCK, BMI/bit operations, AES/SHA/CRC and flags. Some forms
already exist. Audit by encoding, operand width/type, feature requirement and
state effects, not one yes/no check per mnemonic.

## 1. Inventory before changing instructions

Create the implementation ledger in the existing status/issue workflow, not a
new broad Kamy-versus-CD comparison. For each family record:

- Forms already modeled, native-island forms, specific rejections and invalid
  encodings. Distinguish lift/CFG failure from unmodeled instruction effects.
- Integer/vector/scalar widths, register versus memory operands, immediates,
  implicit operands, prefix/address-size variants and CPU/OS feature gates.
- Read/write/preserved/undefined flags and architectural state; memory effects,
  ordering, fault/trap behavior and available transformation/legalization rules.
- Actual corpus sites and consumer-visible witnesses. Do not count a mnemonic
  as complete when one width or operand direction works.

Subtract the bounded prerequisites already delivered by
[H1](01-unified-rebuild.md#completion-notice) from the residual implementation
matrix, preserving their regressions and shared producer/consumer contracts:

- I8/I16/I32/I64 DIV/IDIV with quotient/remainder projections from one hardware
  division and preserved divide faults.
- Paired low/high multiplication, implicit-register constraints and snapshots.
- High-byte operand reads; this does not establish every high-byte destination
  or encoding form.
- Exact symbolic RIP operands through accepted NativeInline operations and the
  final shared binder.

Record these as predecessor work, not new recovery by this handoff. Recheck the
actual implementation and any additional 02/03 prerequisites before extending
them. H1's rejection of unmodeled native flag reads/writes is containment, not
implemented flag semantics and not completion of #11. Do not credit unchanged
bit-count or other existing operations to H1 without checking their history.

Implement these families in gated milestones. The assignment includes all the
families below; an agent may sequence commits, not stop after the first family
and call #11 complete. The matrix must explicitly identify ISA extensions and
encodings outside the supported target. Do not silently substitute an invented
"full x86" promise or claim untested variants.

## 2. Make flags and native boundaries sound first

- Preserve CF/PF/AF/ZF/SF/OF according to the real instruction and width. Include
  partial writes and independent carry chains; a flag not modified remains the
  incoming value, not an arbitrary zero or the result of a later helper.
- ADC/SBB, carry/borrow producers, ADX where supported, shifts/rotates through
  carry, bit tests, compare/test, LAHF/SAHF and PUSHF/POPF effects need explicit
  dataflow. Preserve privileged/unmodifiable-bit restrictions for user-mode
  flags instructions rather than pretending every bit is writable.
- Handle zero and masked shift counts, width-boundary counts, overflow and
  undefined bits explicitly. Undefined architectural output is not a license
  to drop a defined input dependency or choose behavior inconsistent with the
  source instruction's documented constraints.
- Preserve currently fixed BoolNot and partial-register behavior. High-byte
  register encodability and 32-bit zero-extension remain real constraints.
- Reuse 02's frame-backed state/bounded scratch rules. Selection helpers must
  not accidentally consume or destroy flags that are live through them.
- NativeInline must have explicit effects for all accepted reads/writes,
  implicit operands, flags, memory, stack and control state. Preserve #8's
  after-definition/pin/write-reservation behavior through memory-backed lowering.
  Decoder register-use metadata alone is not a complete memory/flags model.
- Re-enable currently rejected flag-reading native forms only after producer,
  optimizer, allocator and selector preserve the dependency. Raw rflags bytes
  with no SSA inputs must not bypass DCE and correctness checks.
- Symbolic/RIP/absolute operands in accepted native islands must bind through
  the unified linker at final placement. Copying raw PC-relative displacements
  is not position-independent re-emission.

## 3. Segmented memory and native-island cutover (#26)

- Do not turn `[gs:offset]` or `[fs:offset]` into flat `[offset]`. Segment bases
  are runtime state; ASLR does not make them zero or part of image relocation.
- Implement the issue's sound native path where appropriate, with complete
  effects and real operand bindings, or use the shared explicit segmented
  memory operation if prior SDK work already introduced it. Do not create both
  as competing conventions.
- Preserve load/store width, effective-address arithmetic/address-size, register
  index/base, source/destination effects, aliases and exception ordering.
  A segment prefix is not proof all remaining operands are relocation-free.
- Windows x64 GS/TEB/TLS uses must execute correctly in host and module code.
  FS behavior must be tested under an appropriate controlled environment; do
  not claim valid arbitrary FS memory simply because no crash was observed on
  one host. Default flat DS/ES behavior and segment-ignored operations such as
  LEA must follow the architecture rather than uniform prefix guessing.
- Do not hardcode TEB/PEB pointers or copy one machine's segment base into the
  output. Preserve the original access so each thread uses its own OS state.
- Report faithful native passthrough as such. It can restore relocation/lowering
  eligibility, but does not make that instruction semantically transformable.

## 4. Implement semantic families end to end

Each new IR operation needs real lifter, optimizer/effect classification,
allocation/location, selection/encoding and reference consumers together.
Format-specific PE state remains outside format-agnostic IR types.

### Integer/bit/BMI and flag-dependent operations

Audit existing bit-count/scan/popcount support before extending. Cover the
assigned BMI/BMI2/ADX/bit-test and relevant carry/rotate forms with their actual
zero-input behavior, width rules, implicit operands and flag semantics. Distinct
instructions with similar names do not have interchangeable undefined outputs
or CPUID behavior. No host compiler constant-folding away the tested instruction.

### SSE/AVX arithmetic, conversions, compare, shuffle and pack

- Represent scalar versus packed lanes, integer saturation/signedness, rounding,
  conversions, NaN/unordered results, signed zero, denormals and MXCSR-dependent
  behavior as required by the instruction. Do not enable fast-math equivalence.
- Preserve upper-lane behavior: legacy SSE merge semantics differ from VEX zeroing;
  scalar destination lanes and YMM state cannot be reduced to an I128 value.
- Respect CPU plus OS extended-state enablement, instruction feature requirements
  and supported XMM/YMM register classes. No silent new target ISA requirement.
- Floating exception/status effects and trap possibilities are observable. Do not
  DCE/reorder arithmetic as pure integer work when it changes them. Fused versus
  unfused rounding must remain distinct.

### x87 stateful arithmetic and conversions

Model the real extended-precision register stack, TOP/tags, control/status words,
rounding/precision and memory conversion effects for accepted forms. Do not
flatten x87 to host f64 and lose 80-bit or stack semantics. Across joins/calls,
preserve actual x87 stack state and the ABI contract. Unsupported state merges
must fail precisely before output, not be reported as modeled x87 coverage.

### String/REP operations

Cover MOVS/STOS/CMPS/SCAS and required LODS forms, width/address-size/count and
DF behavior, REP/REPE/REPNE termination, pointer updates, flags and memory aliasing.
Zero count must not touch memory. Early stop and overlapping accesses must match
the native operation. Do not replace fault-sensitive native repetition with a
loop that misrepresents partial progress/restart state to the OS; preserve exact
native execution with sound effects when semantic loop expansion cannot prove
those obligations, and do not count that as semantic-op completion.

### Atomic and LOCK operations

Model atomic read-modify-write and compare-exchange as effectful operations,
including success/failure values, accumulator semantics, widths, alignment,
LOCK legality, ordering and flag effects. XCHG's implicit atomic behavior matters.
Do not lower to independent loads/stores, speculate an atomic memory access,
duplicate it through a transform, or claim a single-thread value test proves
atomicity. Keep volatile/atomic/ordinary memory distinctions in optimization.

### AES/SHA/CRC and related special operations

Implement the actual supported forms, state widths, polynomial/bit ordering,
round behavior and CPU features. Use public known-answer vectors and native
cross-checks. Re-emitting a native instruction may be the selected machine form
for a semantic operation; an opaque bytes-only fallback is not its IR semantics.
Do not weaken cryptographic state by truncating lanes or rewriting through an
unverified approximation.

## 5. Prove semantics and recovered eligibility

Required acceptance:

1. For every implemented form, deterministic boundary tests cover widths,
   partial destinations, implicit operands, flags/state, memory direction and
   applicable immediate/addressing variants. Use bit-vector proofs where
   appropriate for integer identities and isolated differential native harnesses;
   do not test only copies of the implementation formula.
2. FP/x87 cases exercise raw bit patterns, NaN/unordered/signed-zero, rounding/
   precision and control/status behavior. Compare outputs/state according to
   documented semantics, not string formatting or approximate equality alone.
3. String cases cover zero count, early exit, DF changes with restoration,
   distinct sizes, overlap where meaningful and observable pointer/count/flag
   results. Fault-sensitive cases use controlled native execution, not invalid
   addresses that crash the entire test runner.
4. Atomic cases include return values and concurrent invariants with controlled
   synchronization, plus memory-effect/ordering checks. Avoid timing/race-based
   pass criteria and unsupported CPU assumptions in committed tests.
5. Segment cases read thread-specific TEB/TLS or controlled state before/after
   relocation, including multi-thread differences and live surrounding values.
   Prove source semantics preserved, not merely a nonzero pointer returned.
6. CPU-specific tests execute only when CPUID and relevant OS state support
   permit them. Record skips; do not claim skipped ISA families were runtime-
   verified or emit substitutes that remove the feature dependency silently.
7. Recover real stable-cohort `UnsupportedInstruction`/operation-caused
   `LiftFailure` cases in host/module identity and supported transformed paths.
   Check that targeted instructions are real SSA semantic ops where promised,
   not renamed NativeInline nodes or newly resident originals.
8. Preserve nonfatal allocation, calls/phis/native state, symbolic references,
   forced ASLR and actual-body unwind. Run the existing corpus plus focused
   fixtures. An unrelated reference/CFG/EH rejection remains independently
   visible; it cannot be counted as an instruction implementation failure or
   hidden to make the operation recovery statistic improve.

## Delivery

Apply the master/extension verification and commit rules. No builds/formatters
against a predecessor's in-flight tree. Do not claim full #11 completion if
assigned forms remain unsupported; retain exact residual rows and explain
which acceptance is incomplete. #26 may close on a proven native path without
claiming that path is an obfuscation pass. Do not reopen #8's fixed bug by title.

Hand 06 a precise exceptional-effect/trap, flag/state and memory/native-boundary
contract. Preserve error locations and source-operation ranges so EH work can
associate synchronous exceptions with their real original protected region.
