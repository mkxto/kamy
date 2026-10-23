---
name: kamy-triage
description: >
  Localize Kamy miscompiles, corpus FAILs, coverage/rejection regressions and
  protected crashes/wrong output with headless corpus, bisect, dump and
  explain-reject commands; inspect SSA, frames, memory homes and boundary pins.
---

# Kamy triage

## Operational checklist

1. **Validate original:** `kamy corpus doctor --corpus <dir> --member <name>`.
   Check independent golden/health; never re-bless protected failures or existing
   members. Preserve originals/goldens. Disclose unavailable/skipped members.
2. **Detect:** `kamy corpus verify --corpus <dir> --member <name> --keep`.
   Keep the exact executed binary plus appended `.debug-map.csv` and
   `.link-report.json`; use `--baseline <file>` for coverage transitions.
3. **Isolate EXE:** `kamy bisect <exe> --expect-exit <code> --expect-stdout <file>
   --stdin-file <input> --timeout <seconds> --keep`. Supply relevant options;
   wrong-output defects need stdout comparison, not exit alone. Every probe AND
   final replay must use the same stdin/timeout/output predicate. Keep the actual
   failing replay artifact in its exclusively reserved directory. All-lowered
   success leaves nothing to bisect. DLL export-call oracles stay with corpus.
4. **Inspect:** `kamy dump <input> --rva <hex> --stage <stage>` separately for
   `lift`, `ssa`, `optimize`, `regalloc` (default `optimize`). Capture stdout,
   stderr/nonzero diagnostics. Inspect source/SSA, transforms, frame coordinates,
   typed homes, saves, bounded scratch and `boundary_pins`, not global registers.
   Frame proof may fail before later stages; use earlier dumps. Authored KAMYMOD
   v2 DLLs auto-detect `.kmod`: RVA means local compiler function entry, NOT host
   source/final RVA. Inspect `source_range`, `native_abi`, `operand_references`;
   `HostImageBase` remains symbolic without a host. Never invent module host RVAs.
5. **Rebuild/prove:** `kamy protect <input> -o <out> --ssa-identity --debug-map
   <csv> --link-report <json>`; also protect with the requested `--profile <yaml>`
   without identity. Inspect exact emitted outputs and compare native values,
   caller state and forced-ASLR body/epilogue unwind. Use `kamy explain-reject
   <input> [--rva <hex>]` for negatives. Preserve witnesses/requested intensity.
   Decode exact original/output bytes: `kamy dump <exact-PE> --stage native
   --rva <hex> --size <decimal-byte-count>`. Use actual output placement RVA/size
   or original module-local range, never source RVA in the output. Nonzero size
   is native-only; decoding requires one file-backed section and whole valid
   instructions. Rows show RVA, preferred VA (NOT runtime ASLR), bytes/Intel
   operands; invalid ranges fail atomically. See tooling reference for details.
6. **Record:** exact commands, tool/build/input/output identities, maps, PC/ABI/
   frame observations, native/scaling evidence and unresolved items in
   `docs/STATUS.md`. Tests/static analysis are not native proof or reacceptance.

IDA/x64dbg are unavailable this campaign: Kamy commands/native Windows execution
must stand alone. Elsewhere, an available debugger is optional single-culprit
inspection only, NEVER the batch pass/fail loop. Do not fabricate missing evidence.

## Safety and interpretation

- **Health before equality:** timeout/missing termination always fails. Corpus
  `expected_exit` optionally requires an exact terminal code; traced faults need
  explicit matching expectation, even without normal exit. Record validated
  traced termination as such. Normal nonzero exits may be valid; NTSTATUS-like
  numbers alone are not fault events. Generic `kamy verify` has no expected-fault
  exception. DLL loaders require exit 0, no traced fault and actual typed returns;
  GUI traces must be nonempty. Equal crashes/empty or invalid goldens cannot pass.
- **Required lowering:** manifest `lower_exports` names HOST exports; each must
  exist and actually lower, regardless of aggregates. Empty means all-functions
  identity. Loader `exports` preserves exact argument tokens/repeated calls.
  Failed requirements retain measured coverage and diagnostics, not empty records.
- **Population/intensity:** separate selected, eligible, lowered, transformed,
  actual intensity and rejection transitions. Compare stable source identities;
  report additions/removals separately. Identity success is not MBA protection.
- **Identity/profiles:** `--no-transform` = `--ssa-identity`, same SSA backend,
  never verbatim relocation. Without a profile, require an identity flag. With profile,
  identity suppresses semantic passes, preserving injection/naming/layout policy
  and strict validation. Host `--only-rva`/`--reject-rva` are mutually exclusive
  and conflict with profiles; use host `!Address`. Selection cannot override safe
  rejection. Resident host bodies stay put but reference operands may be patched.
- **Maps/reports:** require `kamy-debug-map,2` columns
  `origin,source_module,source_symbol,host_source_rva,new_rva`; only host function
  `host_source_rva` selects host dumps/bisection. Authored identities are plugin
  instance + exact compiler symbol; `host-image-base` is an anchor, not function.
  `new_rva` is final image RVA; sizes come from native runtime ranges. No old map
  aliases/fake RVA namespace. Require `kamy-link-report` v1; JSON coordinates are
  numeric, absent identities null. Inspect active placements/directories/ownership;
  certificate `file_offset` is not RVA. Structural reports are not execution proof.
- **D16/D22/D24/D40:** one format-agnostic frame, memory homes, bounded scratch,
  explicit flags, actual-body unwind, one backend/rebuild; table-free recovered
  switches, safe rejection for genuinely unproved semantics. No blanket rejects,
  witness special cases, old allocator, pressure retries or reduced MBA intensity.
- **Quarantine:** historical locked 23-member corpus remains unavailable; disclose
  subset versus full population. `dll_strutil`'s quarantined original MUST NOT be
  restored, rebuilt, re-blessed or have deletion staged. NEVER change security
  settings/exclusions. Skip/disclose, never PASS. Do not replace existing goldens.
- **Scope:** green identity/old campaigns do not establish H2 reacceptance or
  authorize H3–H7, std/startup/lifecycle/whole-image-compaction claims.

## References

- Commands, profile/schema/ABI/module semantics: `docs/tooling.md`.
- Frame/save/unwind contracts: `docs/architecture.md` §8.1; decisions:
  `docs/grilling.md` D16/D22/D24/D40.
- Acceptance and evidence: `docs/handoffs/02-memory-backed-lowering.md`,
  `docs/STATUS.md`. Keep historical snapshots there, not in this checklist.
