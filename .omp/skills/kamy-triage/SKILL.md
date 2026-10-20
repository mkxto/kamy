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
4. **Deep-dive (last resort)** — only now open the single isolated culprit in
   x64dbg to step instructions. x64dbg is **never** the batch pass/fail loop.

## Tool quick reference

| Command | Use |
|---|---|
| `kamy corpus verify [--member N] [--keep] [--baseline F] [--write-baseline F]` | run the differential corpus; `--keep` retains the protected artifact |
| `kamy corpus doctor` | assert each oracle reproduces its golden on the *unprotected* original — run this first if an oracle looks wrong (catches ABI/call-shim bugs) |
| `kamy bisect <bin> --expect-exit <n> [--stdin-file F] [--timeout S]` | isolate the miscompiling function set |
| `kamy dump <in> --rva <hex> [--stage lift\|ssa\|optimize\|regalloc]` | one function's IR + allocation |
| `kamy explain-reject <in> [--rva <hex>]` | why a function was left unlowered; per-function reason (not aggregate) |
| `kamy protect <in> -o <out> --ssa-identity [--only-rva H,..] [--reject-rva H,..]` | SSA-identity protect; the rva flags force lowering on/off per function |

## Rules & gotchas

- **SSA-only is the design.** Verbatim relocation is a banned weakness (D22);
  deselected functions (`--only-rva`/`--reject-rva`) are rejected **in place**,
  byte-identical, never relocated. If a tool ever relocates verbatim, that is a
  bug — stop and report, do not paper over it.
- **`bisect` needs a real pass/fail signal:** the original's exit code
  (`--expect-exit`). If the all-lowered build already passes, bisect correctly
  reports "nothing to bisect" — the binary has no miscompile.
- **Corpus tools need the checkout:** pass `--corpus <dir>` or set
  `KAMY_CORPUS_DIR`. `console_cfg`/`console_cfg_lto` are the known-FAIL members.
- **Runner is headless by construction:** every launch goes through `kamy-run`
  (job-object, WER-popup suppressed, hang-killed) — no WER dialogs, no orphaned
  children, safe to run in bulk and in parallel.

Full command surface and flags: `docs/tooling.md`. Decision context: `docs/grilling.md` (D22).
