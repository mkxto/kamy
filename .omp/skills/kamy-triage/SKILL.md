---
name: kamy-triage
description: >
  Localize and inspect kamy SSA-backend miscompiles with the headless in-tree
  tools instead of ad-hoc debugging. Use when a protected binary crashes or
  diverges from the original, a `kamy corpus verify` member FAILs, SSA coverage
  drops or reject counts move, or you need to find which function miscompiled,
  read its lifted/optimized IR and register allocation, or learn why a function
  was rejected. Triggers: "miscompile", "corpus FAIL", "which function broke",
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

1. **Detect** — `kamy corpus verify --member <name>` reproduces the FAIL and
   prints exit + coverage. Add `--baseline <file>` to diff coverage/reject
   counts against a saved snapshot and catch silent regressions.
2. **Isolate** — `kamy bisect <binary> --expect-exit <code>` ddmin-narrows the
   SSA-lowered set to the minimal function(s) whose lowering flips pass→fail,
   and reports the faulting RVA. This replaces manual bisection.
3. **Inspect** — `kamy dump <input> --rva <culprit> --stage regalloc` shows the
   function's IR, `reg_pins`, and the value→register `assignments`. Use
   `--stage lift|ssa|optimize` to see which pass corrupted it.
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
| `kamy corpus verify [--member N] [--keep] [--baseline F] [--write-baseline F]` | run the differential corpus; `--keep` retains the protected artifact |
| `kamy corpus doctor` | assert each oracle reproduces its golden on the *unprotected* original — run this first if an oracle looks wrong (catches ABI/call-shim bugs) |
| `kamy bisect <bin> --expect-exit <n> [--expect-stdout F] [--stdin-file F] [--timeout S]` | isolate the culprit set; a crash (any fatal exception) counts as fail, `--expect-stdout` also catches wrong-output/same-exit |
| `kamy dump <in> --rva <hex> [--stage lift\|ssa\|optimize\|regalloc]` | one function's IR + allocation |
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
- **`bisect` oracle:** the original's exit code (`--expect-exit`); a crash (AV,
  stack overflow, any fatal exception) is an unexpected exit and counts as fail.
  Add `--expect-stdout <file>` to also catch wrong-output miscompiles that exit
  cleanly. If the all-lowered build already passes, bisect reports "nothing to
  bisect" — no miscompile.
- **Corpus tools need the checkout:** pass `--corpus <dir>` or set
  `KAMY_CORPUS_DIR`. Consult the latest evidence in `docs/STATUS.md`; historical
  known-FAIL lists are not current verdicts. Compare a stable function population
  and report additions/removals separately from reject transitions. Identity
  lowering measures backend coverage, not actual MBA transformation.
- **Runner is headless by construction:** every launch goes through `kamy-run`
  (job-object, WER-popup suppressed, hang-killed) — no WER dialogs, no orphaned
  children, safe in bulk and in parallel. On a crash it reports the faulting RVA
  + NTSTATUS for any unhandled exception, not just access violations.

Full command surface and flags: `docs/tooling.md`. Decision context:
`docs/grilling.md` (D22/D37/D40). Memory-backed allocation, compiled startup,
Rust std/runtime support and whole-image compaction have separate ordered
handoffs; do not infer their implementation from a green identity run.
