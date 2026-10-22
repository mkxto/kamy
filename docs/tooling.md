# Agent tooling

Headless commands for localizing and inspecting miscompiles. These are the
inner loop: they run without a debugger, decide pass/fail on their own, and
scale to a corpus. Reach for x64dbg only after they have narrowed the problem
to a single function.

Diagnostics go to stderr; command results go to stdout.

## Commands

### `kamy protect <input> -o <out> [--profile <yaml>] [--no-transform | --ssa-identity] [--only-rva <hex[,hex...]> | --reject-rva <hex[,hex...]>] [--debug-map <csv>] [--link-report <json>]`

`--no-transform` and `--ssa-identity` are equivalent semantic-identity flags.
Without a profile, they run the canonical SSA identity path: lift → SSA →
optimize → regalloc → lower, without semantic transforms. There is no verbatim
relocation path. `--only-rva` restricts host SSA selection to the listed
functions; `--reject-rva` excludes them. These selectors are mutually exclusive
and conflict with `--profile`, including profile-plus-identity. Use profile
`!Address` selectors for profile runs. RVA lists accept an optional `0x` prefix,
are comma-separated and use base 16. Selection never overrides safe rejection.

Resident and deselected host bodies stay at their original locations. Their reference
operands may still be patched to moved functions; this is mandatory for thunk-free
reference rewriting, so residency does not promise byte-identical bodies.

`--profile <yaml>` applies profile selection and nonsemantic policy. Adding
either identity flag suppresses semantic passes while preserving configured
injection, section naming and supported layout behavior. Unsupported settings
still fail validation. Both identity flags together have the same meaning as
either flag alone. Without a profile, at least one identity flag is REQUIRED.

Profile selector entries consume actual source-qualified function metadata,
not fabricated empty CFGs. Empty `symbols:` selects all entries; otherwise
`!Name`, `!Pattern`, `!Group`, `!Address` and `!TopXref` select their union.
`!Pattern` supports `*` and `?`. Groups are cycle-guarded. Host labels use known
names or `sub_<rva>`; authored names are qualified as `plugin::symbol`.
`!Address` accepts host RVA or image VA only, never a module-local numeric
coordinate; out-of-range values and ambiguous RVA/VA matches fail explicitly.
`!TopXref` uses the host call graph. Exclusion patterns match those same names
and win over every profile, including empty/all and grouped selection. Among
remaining matches, the first profile owns the function; later profiles neither
replace its passes nor accumulate another pass list. Results are deterministic
in symbol order. Deselected authored functions remain required linked module
code, without semantic transformation; they are not silently omitted.

Profiles are validated against the implemented subset, including when semantic
identity is requested. Successful parsing of a target-schema field does not
mean its behavior is supported:

| Setting | Current contract |
|---|---|
| Passes | Only `MixedBooleanArithmetic`; every entry runs in declared order |
| MBA semantics | `add`, `sub`, `xor`; enabled `and`, `or`, `not`, `neg` fail |
| MBA widths | `bit8`, `bit16`, `bit32`, `bit64` |
| MBA probability | 0–100; values above 100 fail |
| Other passes | `ObscureReferences`, `ObscureConstants`, `MutationEngine`, `LoopEncodeSemantics` fail |
| Module settings | Enabled `import_protection`, `obscure_entry_point`, `clear_unwind_info`, `fake_pdb_string` fail |
| Assembler | `shuffle_basic_blocks: true` fails |
| Optimizer | All four settings MUST remain true; disabling one fails |
| Lifter | `lift_calls: true` and `calling_convention: WindowsAbi`; `max_stack_copy_size` and `split_on_calls_fallback` MUST be omitted |

The four optimizer settings are `constant_propagation`, `instruction_combine`,
`dead_code_elim` and `prune_useless_block_params`. Omitted supported settings
use the engine's defaults. `max_stack_copy_size` and
`split_on_calls_fallback` have no implementation consumer; every explicit
value fails, including the historical `512` and `true` values. Unknown fields
are rejected, not silently accepted.
Errors identify the profile index/name and pass index or setting path.
This milestone does not implement additional protective passes to satisfy the
larger target schema. Pressure-based retries remain a backend limitation;
selected, eligible, lowered and actually transformed counts are separate, with
the effective intensity histogram taken from successful per-function reports.
An identity-lowered function is not an MBA-protected function.

Protection targets Windows x86-64 PE32+ only. Profile-driven section naming is
optional and off by default. Semantic identity without a profile uses default
names; profile-plus-identity preserves the profile's naming policy.

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

`--debug-map <csv>` writes a versioned UTF-8 CSV for identity and profile runs:

```csv
kamy-debug-map,2
origin,source_module,source_symbol,host_source_rva,new_rva
host,,host:0x00001400,0x00001400,0x00009000
authored,integrity,compiler_symbol_identity,,0x00009200
```

Rows follow the link report's `SymbolId` order. `new_rva` is the actual final
image RVA, not a VA. Host function rows have `host_source_rva`; `source_module`
is empty and `source_symbol` is `host:0x` followed by eight hexadecimal digits.
Authored rows use the plugin instance name and the exact compiler symbol
identity, not a display name or invented source RVA. Generated rows use
`origin=generated` and their helper symbol name, without a host RVA. Fields are
CSV-escaped, including compiler identities containing commas or quotes.
If present, `host-image-base` identifies `__ImageBase` without a host source RVA;
it is an anchor, not a function selector. Existing host IAT storage uses host
identities. Ordinary authored imports remain unsupported in this milestone.

This is a clean schema cutover. Consumers MUST require `kamy-debug-map,2` and
the new columns. The unversioned `old_rva,new_rva` format is obsolete; there is
no compatibility alias or synthetic module-RVA namespace. Use a host row's
`host_source_rva` with `dump --rva` or host-only identity selectors. Authored
symbols are not host source addresses. The map does not promise function
lengths; consult the final PE Exception table for native runtime ranges.
Map filesystem errors fail the command with path context.

```sh
kamy protect app.exe -o app.kamy.exe --ssa-identity --only-rva 0x1400,0x1860
```

`--link-report <json>` serializes the structural link report with
`"schema": "kamy-link-report"` and `"version": 1`:

- `functions[]`: `symbol`, `selected`, `eligible`, `lowered`, `transformed`,
  `intensity`. These are separate axes, not synonyms for a moved address.
- `placements[]`: `symbol`, numeric `rva`, numeric `size`, and lowercase
  `ownership` (`retained`, `resident`, `generated`, `retired`).
- `directories[]`: numeric `index`, `rva`, `size`, numeric/null `file_offset`,
  and `contributions[]` using the same placement shape. Ordinary RVA
  directories have null `file_offset`; certificate index 4 uses its actual
  final file offset and RVA zero, without an address-map row. Inspect active
  targets and ownership; section counts alone cannot detect redundant tables.
- `rejections[]`: `symbol` and structured rejection `reason` tag.

Each JSON symbol has `origin`, `source_module`, `source_symbol` and
`host_source_rva`. Inapplicable module/RVA fields are JSON null, not invented
numeric coordinates. Origins include `host`, `authored`, `generated`,
and `host-image-base`; the image-base anchor uses `__ImageBase` without a host
source RVA. Unlike hexadecimal CSV values, JSON coordinates are
numbers. This report exposes final linker data; it is not proof of runtime
execution, reference completeness or whole-image compaction.

### `kamy plugin build --manifest-path <Cargo.toml> -o <plugin.dll> [--entry <symbol>] [--linker <lld-link>]`

The SDK and supported plugin authoring language are Rust-only (D39/D40). The
current module workflow uses a freestanding `#![no_std]` Cargo library with
`kamy-sdk` as a path dependency from `crates/kamy-sdk` and this native target:

```toml
[lib]
crate-type = ["staticlib"]
```

No C/C++ headers, compiler or plugin API are needed. The callback receives the
target's original three Win64 entry arguments, not `argc`/`argv`/environment.
`plugin!(initialize)` exports `kamy_plugin_init`; `plugin!(name, initialize)`
exports a custom callback for `--entry name`. The macro owns the freestanding
module's aborting panic handler and, on Windows x64 MSVC, the real 32-bit
`_fltused` data marker initialized to `0x9875`. The retained marker satisfies
LLVM's floating-point runtime reference without loading a CRT. Plugins MUST NOT
provide a second panic handler or link another runtime defining these symbols;
duplicate ownership is an error, not a fallback. This narrow prerequisite does
not supply std, a CRT, math helpers or general Rust runtime support.

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

The command uses Cargo's release profile, fat LTO, one codegen unit and
`panic=abort`, targeting `x86_64-pc-windows-msvc`. A `staticlib` target supplies
the Rust dependency closure to LTO. The post-LTO LLVM IR is consumed by the
version-matched `llc` native emission; ABI machine-state metadata is captured
from that same complete compiler invocation, never by resuming serialized MIR.
Typed IR and the native machine records are associated with compiler symbols,
then checked against native COFF and the linked DLL's contribution provenance.
This is not a claim of a vendor Rust ABI exporter or stable internal Rust ABI.

Install the Rust toolchain's matching LLVM tools. By default, the producer finds
`llc` under the active rustc sysroot's `lib/rustlib/<rustc-host>/bin` directory.
`KAMY_LLVM_TOOLS_DIR` overrides that tools directory. A mismatched LLVM version
fails explicitly; an unrelated system LLVM installation is not a substitute.
The ABI metadata parser is pinned to LLVM **22.1.2** (a Rust version suffix is
allowed), with exact target/data-layout validation. Current modeled ABI types
are `i1/i8/i16/i32/i64`, `f32/f64`, pointers and flattened structs; typed
`byval`/`sret` uses supported aggregate arrays/structs. Default LLVM `ccc` and
`fastcc` are accepted, with actual captured call masks required for `fastcc`.
Vectors, nondefault address spaces, other conventions, variadic calls and
unmodeled/missing machine records fail explicitly. The root callback is checked
against `kamy_sdk::Entry`: three 64-bit pointers in RCX/RDX/R8 and a returning
32-bit integer status in RAX. This metadata matrix does not waive backend
instruction/frame limitations or promise arbitrary aggregate-call execution.
An LLVM `lld-link` executable is also REQUIRED; `--linker` accepts its path.

The resulting self-contained specialized DLL embeds **KAMYMOD schema version
2**, including native symbol/reference provenance and ABI contracts, with
unmerged directories. Version 1 artifacts are rejected with rebuild guidance.
Rebuild every plugin using the current producer; no old-format compatibility
path remains. Inject that artifact, not an ordinary DLL, raw object or metadata
sidecar. Native COFF objects are private intermediates. The tool never loads the
plugin into its own process.

Module imports, TLS, PE export/load-configuration/managed directories,
language-handler unwind and unsupported SSA/operand/frame forms fail
contextually rather than produce partial injection. Host imports/TLS remain
intact. Rust `std` with `panic=abort`, ordinary module imports, runtime/TLS
support and compiled Rust startup are handoff-3 targets, not delivered by this
freestanding workflow. The generated startup loader remains in handoff 1.

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
table-bound slots in initialized module writable data. Their native `.data$...`
contributions MUST be file-backed even though the initial values are null.
Provenance from COFF BSS is rejected with rebuild context: rebuild the artifact
using the current SDK/producer, not a compatibility branch that fills a BSS
tail. Data reference/bounds writes cannot extend initialized raw storage.
Inline mode emits no callback table unless a module declares these bounds;
DLLs need no original-entry landing helper.

```sh
kamy plugin build --manifest-path integrity/Cargo.toml -o plugins/integrity.dll
kamy protect app.exe --profile protection.yml -o app.protected.exe
```

### Portable SDK rebuild fixtures

`tests/sdk-rebuild` contains the portable host/plugin/runtime acceptance harness.
These are invocation instructions, not a claim that every scenario has passed;
consult [STATUS.md](STATUS.md) for exercised results.

```sh
cargo build --release --manifest-path tests/sdk-rebuild/Cargo.toml --bin sdk-rebuild --target-dir target/sdk-rebuild-tools
target/sdk-rebuild-tools/release/sdk-rebuild.exe all --out target/sdk-rebuild --kamy target/debug/kamy.exe --cargo cargo --rustc rustc --linker <lld-link.exe> --llvm-tools <matching-LLVM-tools-directory> --lib-dirs <semicolon-separated-WindowsSDK-UCRT-MSVC-library-directories>
```

`build` creates real EXE/DLL hosts. `produce` invokes `kamy plugin build` for
Rust dependency, ABI, ordering, bounds, fast-fail and pressure fixtures and
writes profiles with relative plugin paths. `run` executes actual outputs
through `kamy-run` with structural provenance and native unwind oracles. `all`
runs those phases in order. Tool and library directories are explicit runtime
inputs, not committed host paths.
The full matrix includes ordered EXE/DLL callbacks in inline/init-table modes,
both profile-plus-identity and an ordered two-entry MBA profile (`sub`, then
`add`), qualified callback selectors and `.cache` naming. Identity reports MUST
show no semantic transformation; MBA scenarios require actual lowered and
transformed callback-module reports, not merely successful selector matches.
Contextual unsupported-request/flag-conflict cases and disabled nonexistent
plugin paths are separate subprocess oracles. A harness invocation is still
not evidence until its actual outcomes are recorded in STATUS.
Native unwind probes use source-symbol `Placement` identity to keep the logical
function start distinct from a Version-2 state-fragment begin. The harness
passes decimal coordinates as `origin@function-start:exact-probe-pc:function-end`
through `SDK_UNWIND_PROBES` (`origin` is `generated` or `authored`). It decodes a
straight-line real prologue, including ENDBR/NOP prefixes, allocations and
GPR/XMM saves/frame setup, to construct an independent expected context. It
then uses native runtime lookup and `RtlVirtualUnwind` at that exact PC.
Expected frame state MUST NOT come from the unwind metadata being checked.
One post-prologue witness per logical placement is not every-fragment runtime
coverage or a general CFG emulator; every Exception range is still checked
structurally. Unsupported oracle prologue construction fails explicitly.

The default `--scope full` exercises the original combined bounds-check/counter
callback intact. Its exact plugin-scoped `cannot pass SSA/codegen:
RegisterPressure` diagnostic is reported as `EXPECTED_LIMITATION` for handoff 1,
not pressure recovery. Other failures are fatal. If the callback lowers, the
harness executes it and checks its bounds guard and ordered effects; it cannot
substitute a split/simplified program. Handoff 2 still MUST recover this witness
without reduced requested intensity.

`--scope preserved` reports the combined pressure witness `NOT_RUN` but retains
the mandatory ABI and preserved-pipeline cases. It is a preservation subset,
never proof of pressure/frame recovery. Use actual full-run output, not a
subset's success, when reporting which milestone cases were exercised.

### `kamy dump <input> --rva <hex> [--stage lift|ssa|optimize|regalloc]`

Print the IR for one function at a chosen pipeline stage. Default stage is
`optimize`. Use `regalloc` to see the lowered form that feeds codegen — the
stage where miscompiles usually surface.

```sh
kamy dump app.exe --rva 0x1860 --stage regalloc
```

For a schema-2 specialized module DLL, the same command auto-detects `.kmod` and
interprets `--rva` as that artifact's **local compiler function entry**, not a
host RVA, final output RVA or synthetic module address. It uses the shared
`kamy_link::module::AuthoredSource` adapter consumed by module planning, including
exact code boundaries, operand provenance and native ABI; no host discovery seed
is required. The dump prints source identity/range, `native_abi`,
`operand_references`, IR, pins and allocation. Without a host input,
`HostImageBase` remains symbolic. A register-allocation failure includes the
preceding authored dump in its error body and exits nonzero; diagnostics are
not a successful lowering result. Ordinary host discovery remains unchanged.

An injection failure already naming `plugin::function` can be inspected directly
in its original authored DLL. Do not pass a module's final map RVA to host
`dump --rva`, or invent a host source RVA to make bisection find it.

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

Coverage records distinguish `selected`, `eligible`, `ssa_lowered` and
`transformed`, with `actual_intensity` mapping successful lowering intensities
to function counts. `rejected`/`by_reason` remain rejection accounting, not
protection. Historical baselines lack the newer axes; missing fields read as
zero/empty unknown history, not inferred transformation. Compare unchanged
source-function identities and rejection transitions, reporting population
additions/removals separately from recovery. A green identity verdict does not
prove a configured MBA pass ran or a required authored callback was lowered.

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
- Host RVA identity selection uses `kamy-core`
  (`FunctionSelector::{only, reject}`), consumed by
  `protect --only-rva/--reject-rva`. Profile selection uses source-qualified
  metadata and linker `Options.selected_symbols`; it does not synthesize module
  source RVAs to reuse host selectors.

## x64dbg policy

x64dbg MCP is for interactive deep-dive on a single, already-isolated culprit —
never the batch pass/fail loop. All corpus-scale and bisection pass/fail
decisions run through the headless `kamy` tools above. Do not script x64dbg to
evaluate many functions; that is what `corpus verify` and `bisect` are for.

## Skill

This workflow ships as a repo-local skill at
`.omp/skills/kamy-triage/SKILL.md`; it auto-triggers on miscompile / corpus-FAIL
/ coverage-regression tasks and points back to this document.
