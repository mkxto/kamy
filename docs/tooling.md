# Agent tooling

Headless commands for localizing and inspecting miscompiles. These are the
inner loop: they run without a debugger, decide pass/fail on their own, and
scale to a corpus. Reach for x64dbg only after they have narrowed the problem
to a single function.

Diagnostics go to stderr; command results go to stdout.

## Commands

### `kamy protect <input> -o <out> --ssa-identity [--only-rva <hex[,hex...]>] [--reject-rva <hex[,hex...]>]`

SSA-identity protect: run each function through lift → SSA → optimize →
regalloc and lower it back unchanged, exercising the full pipeline without
semantic transforms. `--only-rva` restricts the move set to the listed
functions; `--reject-rva` excludes them. RVAs accept an optional `0x` prefix
and are comma-separated, base 16. `--no-transform` and `--profile` are
unchanged.

```sh
kamy protect app.exe -o app.kamy.exe --ssa-identity --only-rva 0x1400,0x1860
```

### `kamy dump <input> --rva <hex> [--stage lift|ssa|optimize|regalloc]`

Print the IR for one function at a chosen pipeline stage. Default stage is
`optimize`. Use `regalloc` to see the lowered form that feeds codegen — the
stage where miscompiles usually surface.

```sh
kamy dump app.exe --rva 0x1860 --stage regalloc
```

### `kamy bisect <input> --expect-exit <int> [--expect-stdout <path>] [--stdin-file <path>] [--timeout <secs>]`

Binary-search the set of protected functions to the minimal culprit set whose
protection makes the program diverge. Each probe protects a candidate subset,
runs it headless, and checks the observed exit code against `--expect-exit`; a
crash counts as divergence (any unhandled exception terminates with its NTSTATUS
as the exit code). Add `--expect-stdout <file>` to also require matching output
(trailing whitespace ignored), which catches wrong-output miscompiles that still
exit cleanly. `--stdin-file` feeds the run's stdin; `--timeout` defaults to 30
seconds. Reports the culprit RVAs, candidate count, and step count.

```sh
kamy bisect app.exe --expect-exit 0 --stdin-file input.bin --timeout 30
```

### `kamy explain-reject <input> [--rva <hex>]`

Report why functions were rejected (the `RejectionReason` per function). With
`--rva`, explain a single function; without it, summarize all rejects.

```sh
kamy explain-reject app.exe --rva 0x1400
```

### `kamy corpus verify [--corpus <dir>] [--member <name>] [--keep] [--baseline <file>] [--write-baseline <file>]`

Protect and run every corpus member, collecting coverage. `--member` limits the
run to one member; `--keep` retains the protected artifacts; `--baseline`
compares coverage against a saved baseline and reports the delta;
`--write-baseline` saves the current coverage as the new baseline.

```sh
kamy corpus verify --corpus corpus --baseline cov.json
kamy corpus verify --member hello --keep --write-baseline cov.json
```

### `kamy corpus doctor [--corpus <dir>]`

Health-check the corpus: report each member, whether it is well-formed, and any
problems found.

```sh
kamy corpus doctor --corpus corpus
```

Unchanged commands: `kamy analyze`, `kamy verify --original --protected`,
`kamy corpus build|bless|list`.

## Miscompile-hunt workflow

Work from the cheapest, broadest signal to the most expensive, narrowest one.
x64dbg is the last step, on one function, never the batch loop.

```
corpus verify  →  bisect  →  dump --stage regalloc  →  x64dbg (deep-dive only)
```

1. `corpus verify` — catch a regression across the corpus; diff coverage
   against a baseline.
2. `bisect` — isolate the minimal set of culprit functions on a failing member.
3. `dump --stage regalloc` — inspect the lowered IR of the one culprit.
4. x64dbg — manual deep-dive on that single isolated culprit, only when the IR
   does not already explain the fault.

## Crates

- `kamy-run` — headless job-object runner. Launches the protected binary with
  WER suppressed, kills it on hang, and reports the exit code plus, on any
  unhandled (second-chance) exception (access violation, stack overflow, …), the
  faulting RVA (resolved from image base) and its NTSTATUS code.
- `kamy-triage` — the triage API behind these commands: `protect_identity`,
  `dump_function`, and `bisect`.
- Function selection lives in `kamy-core` (`FunctionSelector::{only, reject}`),
  consumed by `protect --only-rva/--reject-rva`.

## x64dbg policy

x64dbg MCP is for interactive deep-dive on a single, already-isolated culprit —
never the batch pass/fail loop. All corpus-scale and bisection pass/fail
decisions run through the headless `kamy` tools above. Do not script x64dbg to
evaluate many functions; that is what `corpus verify` and `bisect` are for.

## Skill

This workflow ships as a repo-local skill at
`.omp/skills/kamy-triage/SKILL.md`; it auto-triggers on miscompile / corpus-FAIL
/ coverage-regression tasks and points back to this document.
