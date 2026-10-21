# Agent tooling

Headless commands for localizing and inspecting miscompiles. These are the
inner loop: they run without a debugger, decide pass/fail on their own, and
scale to a corpus. Reach for x64dbg only after they have narrowed the problem
to a single function.

Diagnostics go to stderr; command results go to stdout.

## Commands

### `kamy protect <input> -o <out> --no-transform [--only-rva <hex[,hex...]>] [--reject-rva <hex[,hex...]>] [--debug-map <csv>]`

`--no-transform` and `--ssa-identity` run the same canonical SSA identity path:
lift → SSA → optimize → regalloc → lower, without semantic transforms. There is
no verbatim relocation path. `--only-rva` restricts SSA selection to the listed
functions; `--reject-rva` excludes them. These selectors are mutually exclusive.
RVAs accept an optional `0x` prefix and are comma-separated, base 16. Selection
does not override safe rejection.

Resident and deselected bodies stay at their original locations. Their reference
operands may still be patched to moved functions; this is mandatory for thunk-free
reference rewriting, so residency does not promise byte-identical bodies.

`--profile <yaml>` retains profile-driven transforms and symbol selection.

Protection targets Windows x86-64 PE32+ only. Profile-driven section naming is
optional and off by default; `--no-transform` / `--ssa-identity` retain their
existing identity route rather than applying profile settings.

To rename the obfuscator-owned code, metadata, and exception-table sections to
the same exact decoy name, add this to the profile:

```yaml
module_settings:
  custom_section_name:
    enabled: true
    value: '.cache'
```

Use `value: ''` with `enabled: true` to blank those names, the section containing
the final entry point, and any recycled live-helper section. With a nonempty
decoy, unrelated resident code sections keep their names, and a recycled helper
section remains `.text`. Disabled settings ignore `value` and use the default
`.kamy` code/metadata and `.pdata` exception-table names.

An enabled name MUST be ASCII, MUST NOT contain NUL, and MUST fit in eight bytes;
invalid values fail profile loading with setting context. Bytes are preserved
exactly, with PE-header NUL padding only, never truncation. Names do not drive
loader or linker correctness: section characteristics and directory RVAs do.
This setting does not enable payload injection.

For identity and profile runs, `--debug-map <csv>` writes the linker's actual
original/final RVA map, sorted by original RVA. The CSV header is
`old_rva,new_rva`; values are `0x`-prefixed hexadecimal RVAs, not image VAs.
Map filesystem errors fail the command with path context.
With SDK plugins, module rows use their collision-free logical target RVAs from
`kamy_link::module::planned_functions`; these identify authored module functions,
not resident locations in the original host PE.

```sh
kamy protect app.exe -o app.kamy.exe --ssa-identity --only-rva 0x1400,0x1860
```

### `kamy plugin build --manifest-path <Cargo.toml> -o <plugin.dll> [--entry <symbol>] [--linker <lld-link>]`

The SDK and supported plugin authoring language are Rust-only (D39). Add
`kamy-sdk` as a path dependency from `crates/kamy-sdk` to a freestanding
`#![no_std]` Cargo library with this native-library target:

```toml
[lib]
crate-type = ["staticlib"]
```

No C/C++ headers, compiler or plugin API are needed. The callback receives the
target's original three Win64 entry arguments, not `argc`/`argv`/environment.
`plugin!(initialize)` exports `kamy_plugin_init`; `plugin!(name, initialize)`
exports a custom callback for `--entry name`. The macro supplies the module's
aborting panic handler; plugins MUST NOT define a second panic handler.

This complete callback checks the host's DOS signature before startup:

```rust
#![no_std]

use core::ffi::c_void;

unsafe extern "system" {
    static __ImageBase: u8;
}

unsafe extern "system" fn initialize(_: *mut c_void, _: *mut c_void, _: *mut c_void) -> i32 {
    let base = core::ptr::addr_of!(__ImageBase);
    if unsafe { base.cast::<u16>().read_unaligned() } == 0x5a4d {
        kamy_sdk::SUCCESS
    } else {
        1
    }
}

kamy_sdk::plugin!(initialize);
```

The command uses Cargo's release profile, native fat-LTO output, one codegen
unit and `panic=abort`, targeting `x86_64-pc-windows-msvc`. A `staticlib` target
lets Cargo provide dependency rlibs to Rust's native LTO rather than leave
unresolved Rust dependency calls or emit linker-plugin bitcode. An LLVM
`lld-link` executable is required; `--linker` accepts its full path. Native
objects are private build intermediates. The resulting specialized DLL contains
versioned compiler-authored code/data/reference metadata and unmerged directories;
inject that artifact, not an ordinary DLL or raw object. The tool never loads it.
Module imports, TLS, PE export directories, language-handler unwind and
unsupported SSA/operand forms fail contextually rather than produce partial
injection. Host imports/TLS remain intact.

Enable an ordered plugin list in the protection profile:

```yaml
version: 1.0.0
module_settings:
  injection:
    enabled: true
    mode: init-table
    plugins:
    - name: integrity
      path: plugins/integrity.dll
profiles:
- name: plugin-protection
  passes:
  - type: MixedBooleanArithmetic
    semantics: { add: true, sub: true, xor: true }
    bitwidths: { bit32: true, bit64: true }
  symbols:
  - !Pattern 'integrity::*'
```

Plugin paths are relative to the YAML file. Names MUST be unique, nonempty and
contain no `::`. Profile selectors use `plugin::symbol`; the same SSA,
transform and unwind pipeline applies to authored functions. An unsupported
module function fails injection, rather than silently skipping that function.

Injection is off by default; a disabled list does not read plugin files. Modes
are `init-table` and `inline`. Both preserve the entry registers and status-check
plugins; nonzero status fast-fails. The EXE table's final in-range callback
tail-transfers to the original nonreturning entry. DLLs tail-transfer separately
and propagate `DllMain`'s return unchanged; callbacks receive each invocation's
original arguments. Injection requires an existing entry point and is prohibited
for kernel images. `declare_init_table!()` optionally exposes linker-filled
table-bound slots in module writable data. Inline mode emits no callback table
unless a module declares these bounds; DLLs need no original-entry landing helper.

```sh
kamy plugin build --manifest-path integrity/Cargo.toml -o plugins/integrity.dll
kamy protect app.exe --profile protection.yml -o app.protected.exe
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
