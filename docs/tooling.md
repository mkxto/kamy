# Agent tooling

Headless detection, isolation, IR inspection and native proof use Kamy commands;
results go to stdout, diagnostics to stderr. Exercised results, build/input/output
identities and unresolved obligations belong in [STATUS.md](STATUS.md), not here.
IDA/x64dbg are unavailable for this campaign. If available elsewhere, use them
only for an optional single-culprit deep-dive, never the batch pass/fail loop.

## Commands

### `kamy protect <input> -o <out> [--profile <yaml>] [--no-transform | --ssa-identity] [--only-rva <hex[,hex...]> | --reject-rva <hex[,hex...]>] [--debug-map <csv>] [--link-report <json>]`

- Windows x86-64 PE32+ only. Without a profile, an identity flag is REQUIRED.
  `--no-transform` and `--ssa-identity` are equivalent (also when both supplied):
  lift → SSA → optimize → regalloc → lower, without semantic transforms.
  No verbatim relocation, pressure retry or reduced requested MBA intensity.
- With a profile, identity suppresses semantic passes but preserves injection,
  naming and supported layout policy. Validation still rejects unsupported settings.
- Host-only `--only-rva`/`--reject-rva` are mutually exclusive and conflict with
  `--profile`, including profile-plus-identity. Lists are comma-separated hex,
  optional `0x`. Use host `!Address` selectors for profile runs. Selection never
  overrides safe rejection.
- Resident/deselected host bodies stay in place, but their reference operands
  may be patched to movers; residency does not imply byte-identical bodies.

#### Profile selection and validation

Selectors consume actual source-qualified metadata. Empty `symbols:` selects all;
otherwise `!Name`, `!Pattern` (`*`, `?`), `!Group` (cycle-guarded), `!Address` and
`!TopXref` select their union. Host labels are known names or `sub_<rva>`;
authored names are `plugin::symbol`. `!Address` accepts host RVA/image VA only;
out-of-range or ambiguous RVA/VA matches fail. `!TopXref` uses the host call graph.
Exclusion patterns match the same names and win over every selection. The first
matching profile owns a function's passes; later profiles neither replace nor
append passes. Results follow deterministic symbol order. Deselected authored
functions remain required linked code, without semantic transformation.

| Setting | Supported contract; other requests fail contextually |
|---|---|
| Passes | Only `MixedBooleanArithmetic`; every entry runs in declared order |
| MBA | `add`, `sub`, `xor`; enabled `and`, `or`, `not`, `neg` fail |
| MBA widths/probability | `bit8`, `bit16`, `bit32`, `bit64`; probability 0–100 |
| Other passes | `ObscureReferences`, `ObscureConstants`, `MutationEngine`, `LoopEncodeSemantics` fail |
| Module settings | Enabled `import_protection`, `obscure_entry_point`, `clear_unwind_info`, `fake_pdb_string` fail |
| Assembler | `shuffle_basic_blocks: true` fails |
| Optimizer | `constant_propagation`, `instruction_combine`, `dead_code_elim`, `prune_useless_block_params` MUST all remain true |
| Lifter | `lift_calls: true`, `calling_convention: WindowsAbi`; omit `max_stack_copy_size` and `split_on_calls_fallback` (every explicit value fails) |

Omitted supported settings use engine defaults. Unknown fields fail. Errors name
the profile index/name and pass index or setting path; parsing a target-schema
field does not establish implementation support. Retired `RegisterPressure`,
`CallerFrameAccess` and `SelfRecursive` tags are not expected-success exceptions.

`module_settings.custom_section_name` is off by default. With `enabled: true`,
a nonempty `value` renames owned code/metadata/exception sections to that exact
name; unrelated resident sections retain names and recycled helpers stay `.text`.
`value: ''` also blanks the final-entry section and recycled live helpers.
Disabled settings ignore `value`, retaining `.kamy`/`.pdata` defaults. Enabled
names MUST be ASCII, NUL-free and at most eight bytes; preserve exact bytes with
PE-header NUL padding, never truncation. Names do not drive linking/loading or
enable injection; characteristics and directory RVAs do.

#### Debug map and link report

`--debug-map` writes UTF-8 CSV for identity and profile runs:

```csv
kamy-debug-map,2
origin,source_module,source_symbol,host_source_rva,new_rva
host,,host:0x00001400,0x00001400,0x00009000
authored,integrity,compiler_symbol_identity,,0x00009200
```

Require schema 2; the unversioned `old_rva,new_rva` format is obsolete, with no
compatibility alias. Rows follow `SymbolId` order and fields are CSV-escaped.
`new_rva` is the actual final image RVA, not VA. Host function symbols use
`host:0x` plus eight hex digits and a `host_source_rva`, with no module. Authored
rows use the plugin instance and exact compiler identity, not a display name or
invented source RVA. Generated rows name helpers without host RVAs.
`host-image-base`/`__ImageBase` is an anchor, not a function selector; existing
host IAT storage uses host identities. Map errors fail with path context.
Function lengths are absent: consult the final PE Exception runtime ranges.

`--link-report` writes `schema="kamy-link-report"`, `version=1`:

| Field | Meaning |
|---|---|
| `functions[]` | `symbol`, separate `selected`, `eligible`, `lowered`, `transformed`, `intensity`, nullable `allocation` |
| `placements[]` | `symbol`, numeric `rva`/`size`, lowercase `ownership`: `retained`, `resident`, `generated`, `retired` |
| `directories[]` | Numeric `index`/`rva`/`size`, numeric/null `file_offset`, placement-shaped `contributions[]` |
| `rejections[]` | `symbol`, structured `reason` tag |

JSON symbols contain `origin`, `source_module`, `source_symbol`,
`host_source_rva`, using null for inapplicable fields. Origins match the map;
coordinates are numbers, unlike hexadecimal CSV. Ordinary RVA directories have
null `file_offset`; certificate index 4 has its actual final file offset and RVA
zero, without a map row. Inspect active targets/ownership, not section counts.
Reports alone prove neither runtime correctness, reference completeness nor
whole-image compaction. Identity lowering is not actual MBA transformation.

Additive version-1 `allocation` fields are `memory_homes`, `gpr_homes`,
`xmm_homes`, `flag_homes`, `frame_size`, `original_frame_size`,
`outgoing_frame_size`, `nonvolatile_saves`, `scratch_gprs`, `scratch_xmms`,
`max_frame_size`. Sizes are bytes; other fields are counts. Null means no
successful allocation report, not a zero-sized frame. Bounds: seven ordinary
scratch GPRs (`RAX/RCX/RDX/R8/R9/R10/R11`), four XMMs (`XMM0`–`XMM3`), 16 MiB
frame; boundary pins do not enlarge scratch pools. Arithmetic/displacements/value
IDs are checked. Distinguish `FrameDynamic`, `FrameConflict`, `FrameOverflow`,
`FrameResourceLimit`, `UnsupportedFlags` rather than calling them pressure.

Original LOW storage, entry-relative incoming coordinates and original outgoing
storage are preserved; generated HIGH homes/copy scratch/saves stay above call
RSP. `outgoing_frame_size` is only the ABI-known minimum shadow/declared argument
span: unknown stack arguments are not guessed absent or copied into an inferred
span. Generated overhead is a multiple of 16. Frame equations and actual-body
unwind contracts: [architecture §8.1](architecture.md#81-code-generation).

### `kamy plugin build --manifest-path <Cargo.toml> -o <plugin.dll> [--entry <symbol>] [--linker <lld-link>]`

Rust-only SDK authoring currently uses a freestanding `#![no_std]` Cargo library,
`crate-type = ["staticlib"]`, and path dependency `crates/kamy-sdk`.
`plugin!(initialize)` exports `kamy_plugin_init`; `plugin!(name, initialize)`
exports the custom `--entry name`. Callbacks receive the original three Win64
entry pointers in RCX/RDX/R8, returning 32-bit status in RAX, not argc/argv/env.
The macro owns the aborting panic handler and Windows x64 MSVC's 32-bit
`_fltused = 0x9875`; duplicate handlers/runtime symbols fail. This supplies no
std, CRT, math helpers or general Rust runtime. The tool never loads plugins.

Builds use release, fat LTO, one codegen unit, `panic=abort`,
`x86_64-pc-windows-msvc`. The static library carries the dependency closure.
Version-matched `llc` emits native code from post-LTO IR; machine ABI records
come from that same complete invocation, never resumed serialized MIR. Typed IR
and machine records bind compiler symbols and are checked against native COFF
and linked contribution provenance, not guessed from names or Win64 defaults.
This is not a stable Rust ABI or vendor ABI exporter claim.

Matching LLVM tools default to the active rustc sysroot's
`lib/rustlib/<rustc-host>/bin`; `KAMY_LLVM_TOOLS_DIR` overrides the directory.
The parser requires LLVM **22.1.2** (Rust suffix allowed), exact target/data
layout, and `lld-link` (`--linker` may supply its path). Unrelated/mismatched
system LLVM fails. ABI types: `i1/i8/i16/i32/i64`, `f32/f64`, pointers, flattened
structs; typed `byval`/`sret` supports aggregate arrays/structs. `ccc` and `fastcc`
are accepted; `fastcc` requires actual captured masks. Vectors, nondefault
address spaces, other conventions, variadics and missing/unmodeled machine
records fail. Metadata support does not waive instruction/frame limits or prove
arbitrary aggregate execution.

Output is a specialized self-contained DLL with **KAMYMOD v2**, exact native
symbol/reference/ABI provenance and unmerged directories. Rebuild v1 artifacts;
no compatibility path. Inject this DLL, not ordinary DLLs, raw objects or
sidecars; COFF is a private intermediate. Module imports/TLS,
export/load-configuration/managed directories, language-handler unwind and
unsupported SSA/operand/frame forms fail contextually, never partially inject.
Host imports/TLS remain intact. Compiled Rust startup, std/imports/runtime/TLS
remain H3 targets; the current generated loader is intentional H1 behavior.

Example ordered module profile:

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

Paths are profile-relative; plugin names are unique, nonempty, without `::`.
The same SSA/backend/unwind handles authored functions; unsupported functions
fail injection, not silently disappear. Injection defaults off; a disabled list
reads no plugin files. `init-table` and `inline` preserve entry registers and
status-check callbacks; nonzero status fast-fails. EXE tables end with an in-range
tail-transfer to the nonreturning original entry. DLLs tail-transfer separately,
preserving `DllMain`'s return and each invocation's arguments. Injection requires
an existing entry point and is prohibited for kernel images.
`declare_init_table!()` optionally exposes linker-filled bounds in initialized,
file-backed `.data$...`, even when initially null; COFF BSS provenance fails with
rebuild context. Bounds/reference writes cannot extend initialized raw storage.
Inline emits no table unless bounds are declared; DLLs need no original-entry
landing helper.

### Portable SDK rebuild fixtures

`tests/sdk-rebuild` is the portable build/produce/run harness. Build its runner:

```sh
cargo build --release --target x86_64-pc-windows-msvc --manifest-path tests/sdk-rebuild/Cargo.toml --bin sdk-rebuild --target-dir target/sdk-rebuild-tools
```

Invoke the resulting `sdk-rebuild.exe <build|produce|run|all>` with complete
`--out`, `--kamy`, `--cargo`, `--rustc`, `--linker`, `--llvm-tools`, `--lib-dirs`,
`--scope` option/value pairs. Unknown/duplicate options fail. `--kamy` names an
already-built current CLI; rustc needs the MSVC target, linker is `lld-link`,
LLVM tools must match it. `--lib-dirs` is one quoted semicolon-separated list of
SDK UM/x64, UCRT/x64 and MSVC/x64 libraries, including real `kernel32.lib` and
`libcmt.lib`; set `LIB` and `CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER` accordingly.
`all` runs build → produce → run; individual phases share `--out` and require
prior artifacts. Use fresh output for acceptance; negatives refuse stale targets.

`build` creates EXE/DLL hosts and the standalone frame DLL, with authoritative
`__chkstk` symbol/ABI from real `libcmt.lib`, not guessed helper bytes.
`produce` builds SDK/ABI/ordering/bounds/fast-fail/combined-pressure plugins and
the runtime-RSP dynamic negative through the same producer; `run` protects and
executes via `kamy-run`. Default `--scope full` requires intact combined callback
execution under identity and ordered MBA (`sub`, then `add`), forced ASLR,
qualified selection, naming, actual lowering/transformation and requested
intensity. Frame exports cover stack/mixed ABI, homes, address-taken locals,
call results, recursion, guard pages and GPR/XMM saves. Dynamic-frame and
unsupported/conflicting requests must fail contextually without output;
disabled injection reads no nonexistent path; fast-fail must prevent host entry.
No pressure exception, split witness, skipped execution or reduced intensity.
Exact acceptance cases: [H2 matrix](handoffs/02-memory-backed-lowering.md#required-acceptance-matrix).

Native probes use logical source-symbol placements, not unwind-fragment starts:
decimal `origin@function-start:post-prologue-anchor:function-end`, comma-separated,
via `SDK_UNWIND_PROBES` (EXE) or DLL argument. Origins: `generated`, `authored`,
and standalone `host`; resolve host source export → placement → final export.
The independent oracle decodes actual prologue/CFG and checks reachable body and
epilogue PCs with `RtlLookupFunctionEntry`/`RtlVirtualUnwind`, synthesizing state
independently of checked metadata. Calls are boundaries, not recursive execution;
unsupported simulation fails. This proves neither arbitrary ISA/EH nor execution
of all corpus paths. `--scope preserved` omits MBA, configuration negatives,
frame runtime/negatives and combined pressure (`NOT_RUN`): preservation only,
never H2 acceptance or H3 startup/std/lifecycle proof.

### `kamy dump <input> --rva <hex> [--stage lift|ssa|optimize|regalloc]`

Default stage: `optimize`. Separate `lift`, `ssa`, `optimize`, `regalloc` dumps
isolate frame proof, transforms and allocation. `regalloc` shows IR plus concrete
frame/saves/copy scratch, resource limits, typed GPR/XMM/Flag `memory_homes`,
`entry_stack_offsets`, `derived_stack_offsets`, `call_stack_deltas` and
`boundary_pins`, not native assembly or global resident-register assignments.
Flags are explicit booleans; constants/proved entry-stack addresses may lack homes.
SSA requires frame proof before transforms, so later stages may fail early with
available IR and `concrete frame reconstruction failed`. Inspect `FrameAddress`,
`FrameOffset`, proof-carrying `FrameIndex`, `FrameLogical`, `StackProbe` and RSP
chains. Only fully proved subtractive pointer pairs become logical scalars;
mixed/call-returned aliases retain runtime coordinates. Host allocation failures
currently print only `register allocation failed: <reason>`: use earlier stages,
capture stderr, and preserve nonzero status as diagnostic, not successful lowering.

For KAMYMOD v2 DLLs, `.kmod` selects the same `AuthoredSource` adapter as linking;
`--rva` is the artifact-local compiler function entry, not host/final RVA.
No host discovery seed is needed. Output includes source identity/range,
`native_abi`, `operand_references`, IR/pins/homes; `HostImageBase` stays symbolic
without a host. Authored allocation errors retain the preceding dump and exit
nonzero. Never fabricate a host RVA for module inspection or host bisection.

### `kamy dump <input> --stage native --rva <hex> --size <decimal-byte-count>`

Decode an exact nonzero u32 byte count in one file-backed PE section, without
discovery, lifting, function-extent inference or live-process reads. `--size` is
required for native and forbidden on IR stages. Use coordinates from that exact
original/protected PE's map/report: final placement RVA/size for emitted output,
actual module-local RVA for authored originals, never an invented host address.
The map has no lengths; use exact placement/runtime ranges to choose the span.
Header reports half-open RVA range, size and preferred PE image base; instruction
rows contain RVA, preferred VA, exact hex bytes and Intel operands (including
RIP-relative form). Preferred VA is NOT runtime ASLR VA. Unmapped, virtual-only,
cross-section, truncated, overflowing or invalid/partial-instruction ranges fail
with context and no partial output. Decode aligned instruction boundaries; do
not widen a failed range by guessing. This is inspection, not execution proof.

### `kamy bisect <input> --expect-exit <int> [--expect-stdout <path>] [--stdin-file <path>] [--timeout <secs>] [--keep]`

Narrow the lowering set to a minimal culprit set. Every probe AND final replay
use identical stdin, timeout and exit/output predicates. Output comparison ignores
trailing whitespace; require `--expect-stdout` for wrong-output defects with clean
exit. Timeout (default 30 seconds) or missing termination always fails. Unexpected
traced fatal exceptions fail; explicitly declared matching negative faults may
pass. An NTSTATUS-like numeric exit alone is not a fault event.
The final replay must still fail the same oracle; `--keep` retains that exact
executed artifact, not a rebuild. Each invocation exclusively reserves its own
artifact directory; no prior evidence overwrite/PID-reuse collision. Unretained
probes clean only their own directory. Reports include culprit RVAs, candidate/
step counts and replay outcome/artifact. If all-lowered passes, nothing to bisect.
This EXE replay cannot replace a DLL corpus loader's export-call protocol.

### `kamy explain-reject <input> [--rva <hex>]`

Per-function `RejectionReason`; with RVA inspect one function, otherwise summarize
all rejects. A selection request is not evidence of actual lowering.

### `kamy corpus verify [--corpus <dir>] [--member <name>] [--keep] [--baseline <file>] [--write-baseline <file>]`

Protect/run the selected member(s); reject empty/unknown selections. Corpus root:
`--corpus` or `KAMY_CORPUS_DIR`. `--keep` retains the exact executed binary and
appended `.debug-map.csv`/`.link-report.json` sidecars using protect's serializers.
`--baseline` compares coverage; `--write-baseline` saves coverage, never goldens.
Use per-function selection/lowering and source/final maps, not just aggregates.

Coverage separates `selected`, `eligible`, `ssa_lowered`, `transformed`, and
successful `actual_intensity` histogram. `rejected`/`by_reason` are not protection.
Missing newer baseline fields read zero/empty unknown history, not inferred
transformation. Compare stable source identities/rejection transitions; report
population additions/removals separately from recovery. Identity success does
not prove MBA ran or an authored callback lowered.

Manifest `lower_exports` selects named HOST exports for identity lowering;
every export must exist and actually lower. Rejected/selected-but-unlowered is
failure regardless of aggregate coverage; preserve measured coverage/diagnostics.
Empty list keeps all-functions behavior. Loader `exports` is separate: preserve
exact argument tokens and repeated calls to the same export.

Health precedes equality. Manifest `expected_exit` optionally requires the exact
terminal code. Timeout/missing termination fails; a traced fault requires an
explicit matching expectation. Without normal exit, record its validated traced
code in the golden exit field, not as normal termination. Normal nonzero exits
may be valid without an exact expectation. Classify actual runner fault events,
not code ranges. Generic `kamy verify` has no expected-fault exception. DLL loader
runs require exit 0, no traced fault AND actual typed return output; equal empty
failures cannot pass. GUI traces must be nonempty; invalid/empty goldens fail.
Protected observation failures retain coverage and diagnostics.

### `kamy corpus doctor [--corpus <dir>] [--member <name>]`

Run selected unprotected originals against goldens before trusting protected
verdicts. Report health/golden failures; doctor never repairs/re-blesses them.
Disclose unavailable/skipped members; a healthy subset is not full-corpus PASS.

### `kamy corpus bless [--corpus <dir>] [--member <name>]`

Only independently checked NEW originals may establish new goldens, never
protected failures or existing members. `--member` restricts blessing; omission
blesses all members, so always select the intended new member. Empty/unknown
selection fails. Preserve existing originals/goldens unchanged.

Other commands: `kamy analyze`, `kamy verify --original --protected`,
`kamy corpus build|list`.

## Miscompile-hunt workflow

1. **Detect:** selected `corpus doctor`, then `corpus verify --keep`; compare
   health, behavior and stable-population coverage. An exit-only oracle is
   insufficient for wrong results; do not re-bless failures.
2. **Isolate:** `bisect` with the same real EXE input/output/timeout predicate
   through final replay. DLL export calls stay with the corpus loader.
3. **Inspect:** separate `dump` stages `lift`, `ssa`, `optimize`, `regalloc`;
   distinguish host source RVAs from authored local compiler entries.
4. **Prove:** protect exact identity and requested MBA outputs with debug maps
   and link reports; inspect emitted code and compare actual native outputs,
   caller state and forced-ASLR body/epilogue unwind. Run `explain-reject` on
   applicable negatives. Record exact artifacts, commands, observations and
   missing evidence in STATUS; tests/static findings are not native proof.

Keep original witnesses/goldens and requested intensity intact. No blanket
rejection, fixture special case, old allocator or pressure retry. D16/D22/D24/D40
require a format-agnostic shared frame, memory homes, bounded scratch, explicit
flags, actual-body unwind, one backend/rebuild and safe rejection of genuinely
unproved semantics. Recovered switches lower table-free; untouched tables remain
untouched. Details: [decisions](grilling.md), [architecture](architecture.md#81-code-generation),
[acceptance ledger](STATUS.md#post-acceptance-review--2026-10-22).

The historical locked 23-member corpus is unavailable; disclose that separately
from the available checkout/subset. `dll_strutil`'s quarantined original MUST NOT
be restored, rebuilt, re-blessed or have its deletion staged. Never disable or
change security settings/exclusions to recover it. Skip and disclose; never
claim PASS. Keep evidence/source identities in STATUS, not hardcoded snapshots here.
No debugger availability, old campaign results or green identity run authorizes
H2 reacceptance, H3–H7 work or claims of compiled std/startup/whole-image compaction.

## Implementation references

- `kamy-run`: headless job-object runner, WER suppressed, hangs killed; reports
  exit and any unhandled second-chance exception's faulting RVA/NTSTATUS.
- `kamy-triage`: `protect_identity`, `dump_function`, `dump_native`, `bisect` APIs.
- Host selectors: `kamy-core::FunctionSelector::{only, reject}`. Profiles use
  source-qualified metadata and linker `Options.selected_symbols`, never fake RVAs.
- Operational checklist: `.omp/skills/kamy-triage/SKILL.md`.
