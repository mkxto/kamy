# AGENTS.md

Operating guide for agents working in this repository. Not a feature overview —
read `README.md` for that, and the documents below for design intent.

## Source of truth

Design is settled in `docs/`. Treat these as authoritative; do not relitigate
decisions already made there.

- `docs/grilling.md` — decision log **D1–D27**. Every decision is load-bearing.
  Cite the relevant `Dn` when a change depends on one.
- `docs/architecture.md` — pipeline, IR layering, config schema.
- `docs/research.md` — prior art and techniques.

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
  per-function path, avoid needless allocation and copying.

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
convention for an existing concern is a defect.

## Dependencies

Every dependency must pass both gates (grilling **C1/C2**):

1. Somewhat maintained (active, used in the wild).
2. Clearly not worth reimplementing.

Never copy-paste or vendor another project's source. Use crates as Cargo
dependencies; reference designs are fine, lifted code is not. Centralize
versions in the root `[workspace.dependencies]`.

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
