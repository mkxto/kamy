# AGENTS.md

Operating guide for agents working.

## Source of truth

Design is settled in `docs/`. Treat these as authoritative; do not relitigate
decisions already made there.

- `docs/grilling.md` - decision log **D1–D27**. Every decision is load-bearing.
  Cite the relevant `Dn` when a change depends on one.
- `docs/architecture.md` - pipeline, IR layering, config schema.
- `docs/research.md` - prior art and techniques.
- `docs/STATUS.md` - current project status, in phases & milestones

If code and a decision disagree, the decision wins.

**Strict rule — never diverge from the settled plan or research.** The approach
recorded in `docs/` (decisions, `research.md` §-level choices such as the D24
layer 2 use-def DAG + petgraph VF2 engine) is binding. Do not substitute a
different design, shortcut, or "simpler for now" alternative, even if it seems
easier or equivalent. If you genuinely believe the plan or research is wrong,
**stop and prompt the user before diverging** — present the evidence and the
proposed change and wait for an explicit decision. Silent divergence, or
divergence justified only in a commit/report, is prohibited.

## Engineering principles

- Build for the long term. No bandaids, shims, temporary casts, or
  "fix it later" paths. If a thing is worth doing, do it against the real
  data model, not around it.
- Clean cutover. When something is replaced, remove the old path and migrate
  every caller in the same change. No compatibility aliases or dead branches.
- Do not model data that has no producer and no consumer yet. Introduce a type
  when the code that fills it and the code that reads it both exist.
- Correctness first, then six-month maintainability, then speed. In the hot
  per-function path, avoid needless allocation and 

## Agent tooling

Headless triage commands are the inner loop for finding miscompiles; they run
without a debugger and decide pass/fail themselves. Use each for its job:

- `kamy corpus verify` / `corpus doctor` — regression and health across the
  corpus.
- `kamy bisect --expect-exit` — localize a miscompile to the minimal culprit
  function set.
- `kamy dump --rva --stage` — inspect a function's IR (`regalloc` for the
  lowered form that feeds codegen).
- `kamy explain-reject` — report why a function was rejected.
- `kamy protect --ssa-identity [--only-rva/--reject-rva]` — exercise the full
  pipeline as an identity transform on a chosen function set.

**Hard rule.** To localize a miscompile use `kamy bisect`; to inspect IR use
`kamy dump`. x64dbg MCP is deep-dive-only — interactive inspection of a single
already-isolated culprit, **never** the batch pass/fail loop.

See `docs/tooling.md` for the full command reference and workflow.

## Code style

- **Self-explanatory code.** Names carry intent; comments do not restate them.
- **No inline narration.** Do not annotate individual statements. No banners,
  no "// increment i", no describing the next line.
- **Comment only the non-obvious:** a load-bearing invariant, a bit layout, a
  spec quirk (PE/unwind/x86 encoding), or why the obvious approach is wrong —
  with a reference where one exists.
- Public items get a short `///` only when the name plus signature is
  insufficient. Document the contract, not the parameters.
- Match the existing density and voice of the file you are editing.

## Crate boundaries

Format-agnostic core (grilling **D16**): `kamy-core`, `kamy-lift`,
`kamy-transforms`, `kamy-codegen`, `kamy-verify` must carry **no** PE/ELF
assumptions. PE-specific code lives only in `kamy-pe`, `kamy-seh`, `kamy-link`,
and format-specific discovery heuristics in `kamy-disasm`.

Shared types live in `kamy-core` and are consumed, never duplicated. A second
convention for an existing concern is a defect. `kamy-observe` is likewise
format-agnostic shared infrastructure — terminal-first observability consumed
by the front-end, carrying no PE/ELF assumptions.

## Dependencies

Every dependency must pass both gates (grilling **C1/C2**):

1. Somewhat maintained (active, used in the wild).
2. Clearly not worth reimplementing.

Never copy-paste or vendor another project's source. Use crates as Cargo
dependencies; reference designs are fine, lifted code is not. Centralize
versions in the root `[workspace.dependencies]`.

## Error handling & observability

Errors are standardized on `anyhow`. Every fallible fn — public or private —
returns `anyhow::Result<T>`; attach context at each boundary with `.context()`
or `.with_context(|| ...)`, and raise with `bail!`, `ensure!`, or `anyhow!`.
There are no `thiserror` error enums; `thiserror` has been removed from the
workspace. The one exception is `kamy_core::RejectionReason`: it is **domain
data** describing a graceful per-function reject (**D22/D28**), not an error, so
it stays an enum and is never wrapped in an `anyhow` error.

Diagnostics are standardized on `tracing`. The `kamy-observe` crate owns the
global subscriber; only the binary front-end (`kamy-cli`) installs it, via
`kamy_observe::init`. Library crates only emit events and spans — never
`println!` or `eprintln!`.

Severity is a contract:

- `warn!` — graceful degradation of the requested protection: a pass skipped,
  transform intensity reduced (**D28** pressure ladder), register pressure
  forcing a retry or relocation fallback, symbolization below threshold, an
  unsupported construct the lifter cannot model.
- `info!` — high-level milestones with counts: functions discovered, moved and
  rejected totals, the per-reason reject summary.
- `debug!` — per-unit detail: an individual function's reject (address + reason)
  or move, a recovered/failed jump table, a parsed-PE summary.
- `trace!` — per-instruction / per-interval detail.
- `error!` — reserved for the front-end. Library code returns the error with
  `.context()` instead of logging and swallowing it.

Use structured fields, not string interpolation
(`warn!(addr = %rva, reason = %r, "function rejected")`), keep the message a
short static string, and open at most one span per phase or per function —
never per instruction.

Level and per-crate scope are controlled by `KAMY_LOG` (EnvFilter syntax, e.g.
`KAMY_LOG=warn,kamy_link=debug,kamy_transforms=trace`) or the CLI flags `-v`/
`-vv` (info/debug/trace), `-q` (errors only), `--log <filter>`, and
`--log-format <compact|tree|json>`. Diagnostics go to stderr; stdout carries
command results.

## Build & verification gates

Run from the workspace root. The tree must be green before a phase is done.

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo build --workspace --all-targets
cargo test --workspace
```

- Tests must be deterministic and cross-platform. Do **not** commit tests that
  depend on host-specific files (e.g. `C:\Windows\System32\*`); exercise those
  paths from throwaway smoke runs instead.
- Prove behavior by running the changed path, not only by passing tests.

## Commits

- Imperative subject, ≤50 chars, no trailing period.
- Body only for what the diff cannot show (rationale, constraint, rejected
  alternative, spec reference). No bullet list of changed files.
- Never commit a red tree.
