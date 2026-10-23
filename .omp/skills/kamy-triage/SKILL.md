---
name: kamy-triage
description: >
  Localize and inspect kamy SSA-backend miscompiles with the headless in-tree
  tools instead of ad-hoc debugging. Use when a protected binary crashes or
  diverges from the original, a `kamy corpus verify` member FAILs, SSA coverage
  drops or reject counts move, or you need to find which function miscompiled,
  read its lifted/optimized IR, concrete frame, memory homes and boundary pins,
  or learn why a function was rejected. Triggers: "miscompile", "corpus FAIL", "which function broke",
  "bisect", "dump IR / regalloc / reg assignments", "reject reason", "faulting
  RVA", "coverage regression", "protected binary crashes".
---

Hunt kamy miscompiles with the headless tools, in this order. Each step is a
real `kamy` subcommand; do not hand-roll debuggers or drive x64dbg for pass/fail.

## Workflow (do not skip steps)

```
corpus verify  ─▶  bisect  ─▶  dump --stage regalloc  ─▶  x64dbg (deep-dive only)
  detect FAIL      isolate        inspect the one             step the single
                   the culprit    culprit's IR/alloc          isolated culprit
```

1. **Detect** — `kamy corpus verify --corpus <checkout> --member <name> --keep`
   reproduces the FAIL and retains the exact protected binary, schema-2 debug
   map and version-1 link report. Inspect per-function lowering as well as exit,
   output and coverage. Add `--baseline <file>` for coverage/reject transitions.
   Run `corpus doctor` first to validate the original oracle; never re-bless a
   protected failure or use equal crashes/empty loader output as success.
2. **Isolate** — `kamy bisect <exe> --expect-exit <code> --expect-stdout <file>
   --stdin-file <input> --timeout <seconds> --keep` ddmin-narrows the lowering
   set with the same stdin/timeout/output predicate for probes and final replay.
   Retain the actual replayed failing artifact. A DLL export-call oracle belongs
   to the corpus loader, not a bare-DLL EXE replay.
3. **Inspect** — `kamy dump <input> --rva <culprit> --stage regalloc` shows IR,
   the concrete frame, typed memory homes, bounded scratch and `boundary_pins`.
   These pins are ABI/native constraints, not a global resident-register
   assignment. Use separate `--stage lift|ssa|optimize` dumps to locate a bad
   frame proof or optimization; capture stderr and nonzero diagnostic exits.
   For an injection failure already naming an authored function, dump the
   original schema-2 module DLL at its local compiler entry instead. `.kmod`
   selects the same provenance/ABI adapter as linking; no host discovery seed
   is needed. Inspect `source_range`, `native_abi` and `operand_references` before
   IR/pins. Authored regalloc failures print the dump in the error and retain
   nonzero status. `HostImageBase` stays symbolic without a host. Neither the
   authored final map RVA nor a fabricated host RVA is a host bisect selector.
4. **Deep-dive (last resort)** — only now open the single isolated culprit in
   x64dbg to step instructions. x64dbg is **never** the batch pass/fail loop.

## Tool quick reference

| Command | Use |
|---|---|
| `kamy corpus verify [--corpus D] [--member N] [--keep] [--baseline F] [--write-baseline F]` | differential corpus; keep exact protected artifact, debug map and link report |
| `kamy corpus doctor [--corpus D] [--member N]` | selected *unprotected* original must reproduce its golden; disclose unavailable/skipped members; catch ABI/call-shim and health failures |
| `kamy corpus bless [--corpus D] --member N` | bless only the independently checked new original; never existing members or protected output |
| `kamy bisect <exe> --expect-exit <n> [--expect-stdout F] [--stdin-file F] [--timeout S] [--keep]` | same replay oracle/options for every probe and final execution; retain the exact final failing output |
| `kamy dump <in> --rva <hex> [--stage lift\|ssa\|optimize\|regalloc]` | one function's IR, frame, memory homes and boundary pins |
| `kamy explain-reject <in> [--rva <hex>]` | why a function was left unlowered; per-function reason (not aggregate) |
| `kamy protect <in> -o <out> --no-transform [--only-rva H,..] [--reject-rva H,..] [--debug-map F]` | canonical SSA identity; `--ssa-identity` has identical behavior; selectors cannot override safe rejection |
| `kamy protect <in> -o <out> --profile <yaml> --ssa-identity --debug-map <csv> --link-report <json>` | preserve injection/naming while suppressing semantic passes; emit source-qualified maps and structural report |

## Rules & gotchas

- **SSA-only is the design.** Verbatim relocation is banned (D22/D37).
  `--no-transform` and `--ssa-identity` run the same SSA pipeline. Without a
  profile they honor the mutually exclusive host RVA selectors. With a profile,
  either flag suppresses semantic passes but preserves injection/naming policy;
  CLI RVA selectors conflict with profiles (use host `!Address` instead).
  Profiles are still validated; unsupported passes do not become legal in
  identity mode. Resident and deselected host bodies stay in place, never
  relocated verbatim. Their reference operands may still be
  patched to movers; thunk-free reference rewriting requires this, so residency
  does not mean byte-identical bytes. If a tool relocates verbatim, stop and
  report the bug; do not paper over it.
- **Address maps:** `protect --debug-map <csv>` works for identity and profile
  runs. Require first record `kamy-debug-map,2`, then
  `origin,source_module,source_symbol,host_source_rva,new_rva`. Rows are sorted by
  symbol identity and CSV-escaped. Use `host_source_rva` from host function rows
  with `dump --rva`, `--only-rva` and `--reject-rva`. A `host-image-base` row
  is an anchor without a host source RVA, not a function. Authored rows
  identify the plugin instance and exact compiler symbol, never a fake host RVA.
  `new_rva` is the actual final image RVA. The old unversioned
  `old_rva,new_rva` format is obsolete; migrate parsers, do not accept both as
  equivalent. Function sizes are not in this map; consult final native runtime
  ranges. Filesystem errors fail with path context.
- **Structural reports:** `--link-report <json>` requires
  `schema="kamy-link-report"`, `version=1`. Use `placements` and active
  `directories`/`contributions` to inspect helpers, actual runtime ranges and
  ownership. JSON coordinates are numbers; `file_offset` distinguishes a
  certificate directory's file coordinate from RVA directories. The report
  alone is neither runtime proof nor reference-completeness evidence.
- **`bisect` oracle:** require the expected exit and, for wrong-output defects,
  `--expect-stdout <file>`. Timeout or missing termination always fails;
  unexpected traced fatal exceptions fail, but explicitly declared matching
  negative faults are accepted. A numeric exit resembling an NTSTATUS is not
  itself a fault event. Preserve stdin, timeout and output predicate through
  the final replay. Keep its exact output in the invocation's exclusively
  reserved artifact directory; never overwrite prior retained evidence.
  If the all-lowered build passes, there is nothing to bisect.
  The initial access-denied probe cleanup failure was lifecycle-repaired; actual
  stdin/output-aware CLI replay then succeeded (43 candidates, 13 steps, culprit
  `0x19000`). Latest command/log: `target/pre-repair-now/current-bisect.txt`;
  final identities/results: `target/pre-repair-now/receipt.json`.
- **Corpus health:** `expected_exit` optionally declares an exact terminal code.
  A traced fault is allowed only by an explicit matching expectation, even if
  no normal exit event follows; the golden exit field then records that traced
  terminal code, not a normal exit. Timeout/missing termination always fails.
  Normal nonzero exits may be valid without a declaration. Generic differential
  verification has no expected-fault exception. The DLL loader always requires
  exit 0 and actual return output; matching empty failures cannot pass.
- **Required host lowering:** `lower_exports` selects named host exports for
  identity lowering; every listed export MUST exist and actually lower.
  Rejection or absent lowering fails, regardless of aggregate coverage. Empty
  selection retains the existing all-functions behavior. Loader `exports`
  retains exact argument tokens and may call the same selected export twice.
  Preserve actual coverage and diagnostics when a required lowering fails;
  do not replace a failed requirement's measured coverage with an empty record.
- **Corpus source identity:** use `--corpus <dir>` or `KAMY_CORPUS_DIR`. The
  available `C:/dev/kamy-corpus` source HEAD is
  `df9431c03da55fe0432608740ba5d29c78951860` (four historical members);
  fetching locked `d9bc70d9970d3e1988203acd3415b103bcb62197` failed `not our ref`.
  Do not call it the historical locked 23-member campaign. Defender quarantine
  subsequently explained the initially modified `dll_strutil` original; its
  directory is empty. The user directed skipping it; no exclusion/restore was
  executed. Report unavailable/skipped, never PASS or a healthy full baseline.
  Do not rebuild/re-bless/restore it. Preserve all existing goldens and record
  local witness changes separately. Consult `docs/STATUS.md`,
  not historical known-FAIL lists, for evidence. Compare stable populations and
  report additions/removals separately. Identity coverage is not actual MBA
  transformation.
- **Pre-repair #37:** `dll_frame_select` uses `lower_exports: [frame_select]` and
  two six-`u64` loader calls, conditions 0 and 1, args2–4 zero. The independently
  checked original must return arg5 `0x1122334455667788` and arg6
  `0x8877665544332211` respectively. The local source-built original already has
  an independently blessed `expected.yml`; do not re-bless it to match a failure.
  Run selected doctor, then
  `kamy corpus verify --corpus C:/dev/kamy-corpus --member dll_frame_select --keep`.
  After runner-lifecycle repair doctor exited 0, verify exited 1, and coverage
  was 1 selected / 1 lowered / 0 transformed. Condition 0 expected
  1234605616436508552 but observed 500008219856; condition 1 expected
  9833440827789222417 but observed 0. Exit 0 is not this oracle. Keep exact
  binary/maps/report and actual hashes/IR/results; the current retained DLL is
  `C:/dev/kamy-corpus/protected/kamy-protected-dll_frame_select-21892.dll`.
  Final gates passed 455 tests / 47 suites plus fmt/clippy/build; the initial
  451/454 snapshots are historical. NOW evidence net complete includes actual
  CLI replay, not H2 acceptance. Available old
  members console_fibmix/gui_msgbox/kernel32 passed; quarantined dll_strutil is
  skipped, not a full historical four- or 23-member PASS. This is an acceptance
  net, not a backend repair: #37–43 stay unfixed, H2 reopened; #38 producer
  reachability is unresolved and #39–41 have no new timings. No transforms,
  ASan, Rocq, CI or commit/push work.
- **Runner is headless by construction:** every launch goes through `kamy-run`
  (job-object, WER-popup suppressed, hang-killed) — no WER dialogs, no orphaned
  children, safe in bulk and in parallel. On a crash it reports the faulting RVA
  + NTSTATUS for any unhandled exception, not just access violations.

Full command surface and flags: `docs/tooling.md`. Decision context:
`docs/grilling.md` (D22/D37/D40). Memory-backed allocation, compiled startup,
Rust std/runtime support and whole-image compaction have separate ordered
handoffs; do not infer their implementation from a green identity run.
