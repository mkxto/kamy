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
larger target schema. Memory-backed lowering does not retry at reduced MBA
intensity. The historical `RegisterPressure`, `CallerFrameAccess` and
`SelfRecursive` rejection tags are retired, not expected-success exceptions.
Selected, eligible, lowered and actually transformed counts remain separate,
with the effective intensity histogram taken from successful per-function
reports. An identity-lowered function is not an MBA-protected function.

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
  `intensity`, and nullable `allocation`. These are separate axes, not synonyms
  for a moved address. Allocation metrics are additive fields in report version 1.
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

An available `allocation` object records `memory_homes`, `gpr_homes`,
`xmm_homes`, `flag_homes`, `frame_size`, `original_frame_size`,
`outgoing_frame_size`, `nonvolatile_saves`, `scratch_gprs`, `scratch_xmms` and
`max_frame_size`. Null means no successful allocation was reported, not a
zero-sized frame. Sizes are bytes; home/save/scratch fields are counts. The
fixed implementation bounds are seven ordinary scratch GPRs
(`RAX/RCX/RDX/R8/R9/R10/R11`), four scratch XMMs (`XMM0`–`XMM3`) and a 16 MiB
concrete frame. Explicit ABI/native register constraints do not enlarge the
interchangeable scratch pool. Frame arithmetic, displacements and synthesized
value IDs are checked; inspect `FrameDynamic`, `FrameConflict`, `FrameOverflow`,
`FrameResourceLimit` and `UnsupportedFlags` as distinct semantic/resource causes.

`outgoing_frame_size` is the ABI-known minimum shadow/declared stack-argument
span, not the full extent of unknown actual stack arguments. Calls use the
preserved original outgoing storage. Unknown stack arguments remain in the
original frame zone; they are neither guessed absent nor copied into an inferred
span. Generated homes, copy scratch and saves occupy the high zone, above call
RSP. Original negative-offset storage stays in the low zone; incoming home,
stack-argument and return storage retain actual entry-RSP coordinates.
Generated overhead is a multiple of 16, preserving original object/call alignment.

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
Consult [STATUS.md](STATUS.md) for actual exercised results. The commands below
are reproduction instructions, not additional execution or parity evidence.

Run from the checkout root in PowerShell. Supply installed tool/library paths
as script parameters; no particular checkout or machine directory is required:

```powershell
param(
    [Parameter(Mandatory = $true)][string] $Linker,
    [Parameter(Mandatory = $true)][string] $LlvmTools,
    [Parameter(Mandatory = $true)][string[]] $LibDirs,
    [string] $Kamy = "target/debug/kamy.exe",
    [string] $Out = "target/sdk-rebuild",
    [string] $Cargo = "cargo",
    [string] $Rustc = "rustc",
    [ValidateSet("build", "produce", "run", "all")][string] $Phase = "all",
    [ValidateSet("full", "preserved")][string] $Scope = "full"
)
$env:RUSTC = $Rustc
$env:LIB = $LibDirs -join ";"
$env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER = $Linker
& $Cargo build --release --target x86_64-pc-windows-msvc --manifest-path tests/sdk-rebuild/Cargo.toml --bin sdk-rebuild --target-dir target/sdk-rebuild-tools
if ($LASTEXITCODE -ne 0) { throw "building sdk-rebuild failed" }
$HarnessArgs = @(
    "--out", $Out, "--kamy", $Kamy, "--cargo", $Cargo, "--rustc", $Rustc,
    "--linker", $Linker, "--llvm-tools", $LlvmTools,
    "--lib-dirs", ($LibDirs -join ";"), "--scope", $Scope
)
& "target/sdk-rebuild-tools/x86_64-pc-windows-msvc/release/sdk-rebuild.exe" $Phase @HarnessArgs
if ($LASTEXITCODE -ne 0) { throw "sdk-rebuild failed" }
```

`--kamy` MUST name an already-built current CLI. `--cargo` and `--rustc`
select the producer toolchain with the `x86_64-pc-windows-msvc` target installed.
`--linker` selects `lld-link.exe`. `--llvm-tools` MUST contain that rustc's
matching `llc.exe`, subject to the producer's LLVM-version check above.
`--lib-dirs` is one semicolon-separated argument containing the Windows SDK
UM/x64, UCRT/x64 and MSVC/x64 library directories, including `kernel32.lib`
and the real MSVC `libcmt.lib`. Paths containing spaces remain single arguments.
Every phase requires the same complete `--name value` option pairs; unknown or
duplicate options fail. `--scope` defaults to `full`.

`all` runs `build` → `produce` → `run`. To isolate phases, use those values for
`$Phase` with the same `$Out`; `produce` requires the built hosts, and `run`
requires both earlier phases. Use a fresh output directory for a complete
acceptance run. Negative oracles refuse preexisting rejection targets rather
than mistake stale files for current outputs.

`build` creates real EXE/DLL hosts plus `frame-original.dll` from
`tests/sdk-rebuild/hosts/frame.rs`. The standalone frame DLL uses rustc
`opt-level=1`, `panic=abort`, `lld-link`, `/nodefaultlib` and `/entry:DllMain`.
It explicitly links the `libcmt.lib` found in `--lib-dirs` and exports that
library's real `__chkstk` alongside the frame witnesses. Stack-probe recognition
uses the authoritative helper symbol and its exact ABI contract; an anonymous
helper is not guessed from its bytes or RVA.

`produce` invokes `kamy plugin build` for Rust dependency, ABI, ordering,
bounds, fast-fail and combined-pressure fixtures. It writes profiles with
relative plugin paths. It also builds `frame-dynamic.dll`, an ordinary Rust
SDK plugin with runtime-sized inline-assembly RSP adjustment, through the same
compiler/ABI producer. `run` protects and executes real outputs through
`kamy-run`, with structural provenance, behavior and native unwind oracles.

The full matrix includes ordered EXE/DLL callbacks in inline/init-table modes,
profile-plus-identity and an ordered two-entry MBA profile (`sub`, then `add`),
qualified callback selectors and `.cache` naming. Identity reports MUST show
intensity `0.0` and no semantic transformation. MBA scenarios MUST actually
lower and transform both selected callback modules at intensity `1.0`, not
merely match their selectors. The original combined bounds-check/counter
callback MUST remain intact and execute in BOTH identity and ordered-MBA runs,
with `trace=12`, `bounds=24` and forced ASLR. Any protection/runtime failure,
skip, reduced intensity or absent behavior oracle fails full acceptance. There
is no expected-pressure allowance, split/simplified substitute or verbatim
fallback. The `pressure` fixture name identifies this historical witness,
not a current permitted rejection.

The full run also executes the original frame DLL and its identity/MBA outputs
under forced ASLR. All eight selected frame exports MUST lower; identity
transforms zero and MBA transforms all eight at intensity `1.0`. The behavior
oracles cover six-argument and mixed GPR/XMM/stack ABI calls, incoming home and
address-taken local storage, pinned call results, recursion to depth 64 with a
4096-byte original object, a real 24 KiB guard-page frame and a 16 KiB
GPR/XMM-save case. The dynamic-frame plugin MUST package successfully, then
protection MUST fail with `FrameDynamic` naming `plugin dynamic_frame::` and its
compiler symbol, with no `frame-dynamic-rejected.exe`. This is a
strict negative, not a skipped runtime success. Unsupported-request and
flag-conflict subprocesses likewise MUST fail contextually without output;
disabled injection MUST succeed without reading the nonexistent plugin path.
The fast-fail case instead requires native `0xC0000409` and empty host stdout,
proving the original entry did not run after a nonzero callback status.

Native unwind probes use source-symbol `Placement` identity to keep the logical
function start distinct from a Version-2 state-fragment begin. The range format
remains decimal `origin@function-start:post-prologue-anchor:function-end`,
comma-separated. Callback runs pass it through `SDK_UNWIND_PROBES` for EXEs or
the DLL probe argument. Origins are `generated` and `authored`; standalone
frame probes add `host`. Host ranges are derived by matching original exported
RVAs to host source identities, then to their final live placements and exports,
not by treating a final RVA as a source address.

The native oracle first independently decodes the real prologue, including
ENDBR/NOP prefixes, allocation, GPR/XMM saves and frame setup, and validates the
post-prologue anchor. It then walks the logical function's CFG and checks
`RtlLookupFunctionEntry`/`RtlVirtualUnwind` at every reachable instruction PC,
including body and epilogue PCs, using independently synthesized contexts.
It follows both direct branch successors; returns, interrupts/exceptions,
indirect branches and out-of-range tails end that path. Calls are modeled as
boundaries, not recursively executed by the oracle. Expected frame state MUST
NOT come from the unwind metadata being checked. Unsupported prologue/body
simulation fails explicitly; all Exception ranges are also checked structurally.
This is not just one post-prologue witness, nor a claim that all corpus
instructions or paths executed, or that arbitrary ISA/EH behavior is covered.

`--scope preserved` retains host identity and callback identity/ABI cases but
omits ordered-MBA execution, configuration negatives, frame runtime/negative
cases and the combined pressure witness. That witness is reported `NOT_RUN`.
This is explicitly a preservation subset, NOT handoff-2 acceptance. Use an
actual `--scope full` result from [STATUS.md](STATUS.md), never the subset's
success, for claims about exercised recovery. Neither scope delivers compiled
Rust startup, `std`/imports/runtime support or lifecycle changes; those remain
handoff-3 work, and the existing generated loader remains in use.

### `kamy dump <input> --rva <hex> [--stage lift|ssa|optimize|regalloc]`

Print one function's IR at the chosen pipeline stage; the default is `optimize`.
`regalloc` adds the memory-backed allocation that feeds instruction selection,
not final native assembly or a value-to-resident-register assignment table.
Its `allocation: memory-backed` section includes:

- The concrete `frame`: total/original/outgoing sizes, copy scratch and actual
  register saves with offsets.
- `frame_size_limit`, the fixed `scratch_gprs`/`scratch_xmms` pools and
  `memory_homes`, with each value's offset, type and `Gpr`/`Xmm`/`Flag` class.
  Flags use explicit memory-backed booleans, not permanently live EFLAGS.
  Constants and proven entry-stack addresses need not have homes.
- `entry_stack_offsets`, `derived_stack_offsets`, `call_stack_deltas` and
  `boundary_pins`. Pins are ABI/native constraints, not resident live ranges.

SSA construction includes mandatory frame proof before transforms. Therefore
`ssa`, `optimize` and `regalloc` can fail before reaching the requested stage;
the error retains the available IR and reports `concrete frame reconstruction
failed` with its reason. `lift` remains useful for the pre-proof form. Inspect
`FrameAddress`, `FrameOffset`, proof-carrying `FrameIndex`, `FrameLogical` and
`StackProbe` operations alongside the original RSP chain. `FrameLogical`
extraction is limited to fully proved subtractive pointer pairs; mixed or
call-returned aliases retain runtime coordinates, not numeric pointer guesses.

Capture separate stage dumps to isolate frame proof, optimization and allocation:

```sh
kamy dump app.exe --rva 0x1860 --stage lift
kamy dump app.exe --rva 0x1860 --stage ssa
kamy dump app.exe --rva 0x1860 --stage optimize
kamy dump app.exe --rva 0x1860 --stage regalloc
```

A host `regalloc` allocation failure currently returns only
`register allocation failed: <reason>`; it does not retain its preceding IR in
that error. Use the separate `ssa` and `optimize` dumps, and capture stderr as
well as stdout. A nonzero dump exit is a diagnostic, not successful lowering.

For a schema-2 specialized module DLL, the same command auto-detects `.kmod` and
interprets `--rva` as that artifact's **local compiler function entry**, not a
host RVA, final output RVA or synthetic module address. It uses the shared
`kamy_link::module::AuthoredSource` adapter consumed by module planning, including
exact code boundaries, operand provenance and native ABI; no host discovery seed
is required. The dump prints source identity/range, `native_abi`,
`operand_references`, IR, pins and the same frame/home allocation details.
Without a host input, `HostImageBase` remains symbolic. Unlike the host
allocation error, an authored register-allocation failure retains the preceding
authored dump in its error body and exits nonzero. Ordinary host discovery
remains unchanged.

An injection failure already naming `plugin::function` can be inspected directly
in its original authored DLL. Do not pass a module's final map RVA to host
`dump --rva`, or invent a host source RVA to make bisection find it.

### `kamy bisect <input> --expect-exit <int> [--expect-stdout <path>] [--stdin-file <path>] [--timeout <secs>] [--keep]`

Narrow the protected-function set to the minimal culprit set whose protection
makes the program diverge. Every probe and the final replay use the same stdin,
timeout and exit/output predicate. Timeout or missing termination always fails;
an unexpected traced fatal exception fails, while an explicitly declared matching
negative fault is accepted. An exit code that merely resembles an NTSTATUS is
not fault evidence. Add `--expect-stdout <file>` to require matching output
(trailing whitespace ignored), catching wrong-output miscompiles that exit
cleanly. `--stdin-file` supplies stdin; `--timeout` defaults to 30 seconds.
The final replay must still fail that same predicate. `--keep` retains its exact
executed protected artifact, not a newly rebuilt approximation. Each invocation
exclusively reserves its own artifact directory; retained evidence is not reused
or overwritten after PID reuse. Unretained probes clean up only their own
directory. Reports include culprit RVAs, candidate and step counts, and replay
outcome/artifact information.
This is an EXE replay interface, not a replacement for a DLL corpus loader's
export-call protocol.
The initial smoke failed deleting a traced probe; the runner/debugger lifecycle
repair resolved it. The actual stdin/output-aware replay then succeeded with
43 candidates, 13 steps and culprit `0x19000`; retained command/log:
`target/pre-repair-now/current-bisect.txt`. See STATUS and
`target/pre-repair-now/receipt.json` for the latest exercised CLI/artifact hashes.

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

Protect and run corpus members, collecting coverage. `--member` limits the
run to one member. `--keep` retains the exact executed protected binary plus
its debug-map CSV (`kamy-debug-map,2`) and link-report JSON
(`schema="kamy-link-report"`, `version=1`), using the same serializers as
`protect`. Sidecars append `.debug-map.csv` and `.link-report.json` to the
protected binary's full path (for example, `x.dll.link-report.json`). Use
per-function `selected`, `eligible` and `lowered` results and source/final
mappings, not just aggregate coverage, to establish what lowered. Every corpus
command rejects an empty campaign; member selection must identify a real member.
`--baseline` compares coverage against a saved baseline and reports the delta;
`--write-baseline` saves current coverage, not new behavior goldens.

Coverage records distinguish `selected`, `eligible`, `ssa_lowered` and
`transformed`, with `actual_intensity` mapping successful lowering intensities
to function counts. `rejected`/`by_reason` remain rejection accounting, not
protection. Historical baselines lack the newer axes; missing fields read as
zero/empty unknown history, not inferred transformation. Compare unchanged
source-function identities and rejection transitions, reporting population
additions/removals separately from recovery. A green identity verdict does not
prove a configured MBA pass ran or a required authored callback was lowered.

Manifest `lower_exports` is an opt-in list of named **host** exports for identity
selection. Each target is REQUIRED to lower: missing exports, safe rejection or
selected-but-unlowered functions fail the campaign. An empty list retains
all-functions identity behavior. It does not alter `exports`, whose loader calls
still supply exact argument tokens and may call the same export more than once.

Manifest `expected_exit` optionally requires an exact terminal code. Timeout or
missing termination always fails. An actual traced fault is invalid unless
explicitly declared by a matching expected code. That fault can terminate without
a normal exit event; its validated traced code is recorded in the existing
golden exit field, not described as normal exit. Normal nonzero exits remain
valid when no exact expectation is declared. Fault classification uses actual
runner fault events, not an exit-code range or PE/NTSTATUS guess. Generic
`kamy verify` has no expected-fault policy. The DLL loader protocol always
requires exit 0, no traced fault and a real typed return; two failed/empty loader
runs cannot pass by equality. GUI oracles require a nonempty trace. Invalid or
empty golden records fail rather than becoming successful empty comparisons.
Protected observation failures retain coverage and diagnostics. Golden equality
never substitutes for run health.

```sh
kamy corpus verify --corpus corpus --baseline cov.json
kamy corpus verify --member hello --keep --write-baseline cov.json
```

### `kamy corpus doctor [--corpus <dir>] [--member <name>]`

Run each selected unprotected original's oracle against its golden and report
per-member health/golden failures. `--member` limits the health check without
touching unavailable members; disclose skipped members rather than reporting
a subset as a full-corpus PASS. Use this before trusting a protected verdict. Timeout or
a broken loader is never an oracle; only an explicitly declared matching fault
in a policy that permits it is an accepted negative termination. Doctor does
not repair or re-bless a golden.

```sh
kamy corpus doctor --corpus corpus
```

### `kamy corpus bless [--corpus <dir>] [--member <name>]`

Bless goldens from **originals**, never protected output. `--member` restricts
blessing to that member; a missing selection or empty population fails. Omitting
it retains all-member blessing, so use `--member dll_frame_select` when adding
the pre-repair witness and leave every existing original/golden untouched.
Independently check both original return values before blessing.

Unchanged commands: `kamy analyze`, `kamy verify --original --protected`,
`kamy corpus build|list`.

## Miscompile-hunt workflow

Work from the cheapest, broadest signal to the most expensive, narrowest one.
x64dbg is the last step, on one function, never the batch loop.

```
corpus verify  →  bisect  →  dump --stage regalloc  →  x64dbg (deep-dive only)
```

1. `corpus verify` — catch a regression across the corpus; diff coverage
   against a baseline.
2. `bisect` — isolate the minimal set of culprit functions on a failing member.
3. `dump --stage regalloc` — inspect the culprit's IR, concrete frame, typed
   homes, scratch/resource bounds and boundary pins. Use separate `ssa` and
   `optimize` dumps when frame proof or allocation fails, or to isolate a phase.
4. x64dbg — manual deep-dive on that single isolated culprit, only when the IR
   does not already explain the fault.

### Pre-repair #37 corpus witness

The available corpus checkout is `C:/dev/kamy-corpus`, published source HEAD
`df9431c03da55fe0432608740ba5d29c78951860` with four historical members, not the
historical 23-member campaign. The locked revision
`d9bc70d9970d3e1988203acd3415b103bcb62197` could not be fetched (`not our ref`).
Record source HEAD and local witness changes separately from `corpus.lock`;
do not silently relabel the checkout or update historical counts. The initially
modified `members/dll_strutil/orig/dll_strutil.dll` was subsequently confirmed
quarantined by Windows Defender; its original directory is empty. The user
directed that it be skipped; no exclusion or restore was executed. Report it
unavailable/skipped, never PASS. Do not rebuild/re-bless it, modify existing
goldens, or claim a subset establishes a healthy full published baseline. See
[STATUS.md](STATUS.md#now-pre-repair-acceptance-net--not-an-h2-repair) for the
seven-finding acceptance ledger, quarantine evidence and actual results.

`dll_frame_select` selects `lower_exports: [frame_select]`. Its `frame_select`
export accepts six `u64`s; args2–4 are zero, arg5 is
`u64:1234605616436508552` (`0x1122334455667788`), and arg6 is
`u64:9833440827789222417` (`0x8877665544332211`). Two loader calls use arg1
`u64:0` and `u64:1` and independently require arg5 and arg6 respectively.
No `expected_exit` override is needed; the loader must exit 0 with both real
return values. Exit 0 alone cannot detect this confirmed wrong-result defect.

The local member now has a source-built original and independently blessed
`expected.yml`. To reproduce the required failure without changing that golden:

```sh
kamy corpus doctor --corpus C:/dev/kamy-corpus --member dll_frame_select
kamy corpus verify --corpus C:/dev/kamy-corpus --member dll_frame_select --keep
```

Observed after runner-lifecycle repair: the selected doctor exited 0 and
verification exited 1, with **1 selected / 1 lowered / 0 transformed**. Condition
0 expected **1234605616436508552**, observed **500008219856**; condition 1 expected
**9833440827789222417**, observed **0**. The retained artifact is
`C:/dev/kamy-corpus/protected/kamy-protected-dll_frame_select-21892.dll` plus
sidecars. Current logs/baselines use `target/pre-repair-now/current-` prefixes.
This is a real required
failure, not protected correctness success. Re-bless only when independently
establishing a new original, never to accommodate protected output.

Keep the original oracle/golden stable and retain binary/maps/report plus actual
build/input/output hashes, stage dumps and observed values. Required-lowering
failures retain actual coverage and diagnostics. H2 remains reopened and #37–43
unfixed; this acceptance net does not authorize backend repairs, transforms,
ASan, Rocq or CI work, or a commit/push. Bisect must preserve the same real EXE
oracle for probes and replay in its exclusively owned evidence directory; a bare
DLL is not that executable replay contract. The actual stdin/output-aware CLI
smoke with `--timeout 10 --keep` succeeded after lifecycle repair; final gates
passed **455 tests / 47 suites** plus fmt/clippy/build. The NOW evidence net is
complete, not H2 acceptance. The earlier 451/454 gates and failed probe cleanup
are historical snapshots, not the current replay verdict.


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
