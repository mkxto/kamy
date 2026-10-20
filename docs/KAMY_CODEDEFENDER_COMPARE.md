# Kamy vs CodeDefender — technique comparison (independent RE of two example, from CodeDefender plugin SDK that injects some stuff + sw.exe from Kamy, relocations)

Two x64 PE **lifter-based** rewriters (Analyze → Transform → Rebuild). CodeDefender inspired Kamy.

- **CodeDefender** (Aftermath Labs, codedefender.io) — commercial Windows PE obfuscator, x86-64 + ARM64. Pipeline: `AnalyzePE(+PDB) → composable Transform passes → Rebuild`. Observed sample marker `.belabs`: `HelloWorld-Injected.exe` (a *light* profile — import-protection + native rebuild only; no VM/MBA/CFG visible).
- **Kamy** (`.kamy*`) — lift → codegen, **no Transform stage**. Sample: `sw.prot.exe`. Baseline: `sw.exe`.

> Same pipeline *shape*. The gap is (1) a complete **Analyze** stage (refs/unwind/CFG, safe-reject) that lets CodeDefender rebuild cleanly, and (2) a **Transform** stage that is the actual protection. Kamy has neither yet.

## TL;DR

| | CodeDefender | Kamy |
|---|---|---|
| Pipeline | Analyze → **Transform** → Rebuild | lift → codegen (**no Transform**) |
| Transform passes | VM, mutation, MBA, CFG, constants, import-protection, SigBreaker | none |
| Rebuild quality | complete (92–98% coverage, unwind/SEH/CET/CFG-aware) | partial — trampolines + `0xCC` holes |
| Protection value | high (composable) | **≈none** (verbatim relocation) |
| Reversibility | hard (hashed APIs, VM, MBA) | **map `.kamy` back in minutes** |

## CodeDefender — vendor pipeline + observed sample

**Published pipeline:** `Analyze` discovers functions, control flow, references, unwind metadata (optional PDB), and *reports functions it cannot transform safely*. `Transform` applies composable passes per selected function. `Rebuild` emits a native PE (optional debug map), preserving SEH/C++ EH and compatible with CET/CFG/ACG.

**Transform catalog:** advanced code virtualization (key-driven handlers, isolated VM state) · mutation + Mixed Boolean Arithmetic + loop-encoding · control-flow (opaque predicates, indirect branches, block duplication, reference hiding) · constant hardening + **import protection** · SigBreaker binary diversification (instruction reorder, block shuffle).

**Observed in the `.belabs` sample (light profile):**
- **Native rebuild**: EP hijacked to `0x152d` → init-callback array `[payload, original_start]`; CRT startup relocated; Import/Debug/Base-reloc dirs rebuilt into appended sections; fresh `.pdata`. Natural `.text` entropy (no int3 fill).
- **Import protection in action**: `sub_140007000` resolves `user32!MessageBoxA` via PEB `InLoadOrderModuleList` walk + **MurmurHash2** (`0x5BD1E995`), calls `MessageBoxA(0,"Hello World!",…)`. Import DLL list **unchanged** vs clean → the call left no IAT landmark.

### `.belabs` sections
| VA | Flags | Serves |
|---|---|---|
| `0x7000` | R-X | rewritten/relocated code + import-protection thunks |
| `0x8000` | RW | runtime state + init-array bounds (`0x27f0`/`0x2800`) |
| `0x9000` | R | rebuilt Import / Debug / Base-reloc dirs |

## Kamy — observed

Faithful **lift → codegen** relocation, no obfuscation pass → no protection by construction.

- 203 of ~430 functions relocated **verbatim** into `.kamy` (byte-identical to clean; relocated `start` == clean `start`).
- Original `.text` slots overwritten with 5-byte `jmp rel32` + **39,048 `0xCC`** → `.text` entropy **6.43 → 4.40**.
- `.kamy` **plaintext** (ent 6.55). IAT intact/visible. 1:1 trampoline map. PIC (0 new relocs).

### `.kamy*` sections
| VA | Flags | Serves |
|---|---|---|
| `.kamytb 0x22000` | R | relocation/jump-table metadata |
| `.kamy 0x23000` | R-X | relocated bodies (~41 KB, plaintext) |
| `.kamypd 0x2e000` | R | rebuilt exception/unwind table |

## What Kamy can learn from CodeDefender

Not detour tricks — the two missing *stages*:

1. **Complete Analyze → clean Rebuild.** CodeDefender analyzes references + unwind + CFG before rewriting and *rejects* what it can't move safely, so it relocates fully and rebuilds compactly (no trampolines, no int3 holes). Kamy preserves original addresses because it doesn't trust its reference model — that's the root of the `0xCC` (see below).
2. **A Transform stage = the actual protection.** Insert composable IR passes between lift and codegen: mutation / MBA / control-flow / constant hardening / **import protection** / optional VM. Import protection alone (hash-resolved APIs) would sever Kamy's biggest reversing crutch — the visible IAT.

## Why `.text` has `0xCC`, and why a header rewrite won't fix it

Symptom of a **partial, address-preserving rewrite**, not a header choice.

- Kamy moved only 203/430 funcs; ~227 still live in `.text` at original RVAs. Moved funcs leave **interleaved holes** → Swiss cheese, not a truncatable tail.
- Trampolines + holes exist because Kamy **preserves original addresses instead of rebasing references** (callers still `call <orig RVA>`; the stub bridges to `.kamy`).

Shrinking `VirtualSize`/`SizeOfRawData`/`SizeOfImage` only removes a *contiguous dead tail*; live code sits past the holes, so truncation deletes real functions, and sliding survivors down changes their RVAs.

**Short, clean `.text` requires a complete rebuild** — relocate 100% of code and rebase every reference:

| Reference class | fix |
|---|---|
| direct `call`/`jmp` rel32 | repoint |
| rip-relative data | recompute disp |
| jump tables / switch | rewrite entries |
| `.pdata`/`.xdata` unwind | new func RVAs |
| base relocations | new fixups |
| export / TLS / debug / loadcfg dirs | new RVAs |

Then trampolines **and** `0xCC` vanish and `.text` shrinks. This is exactly CodeDefender's Analyze-completeness (the thing that also enables its 92–98% coverage). "Can't compact" and "no protection" are the same missing capability: a complete, rebaseable reference model is the prerequisite for *both* clean rebuild and inserting transforms.

**Cheap interim** (kills the signature, not the size): fill holes with decoy code instead of int3.

## How CodeDefender rewrites a function (per its published pipeline)

To protect the terminal `hello_world()` (clean: `lea rcx,"Hello World!"; call printf`):

1. **Analyze** — recover the function boundary, CFG, references, and unwind info (optional PDB); confirm it's safe to transform or report it.
2. **Transform** — lift to IR and apply the selected passes: import-protection on the `printf`/`MessageBox` call → PEB-walk + MurmurHash2 resolution (exactly what the sample shows); constant hardening on the `"Hello World!"` bytes; mutation/MBA on the surrounding computation; control-flow protection (opaque predicates, indirect branches); optionally virtualize the whole body to VM handlers.
3. **Rebuild** — codegen the transformed function into a new section, register fresh unwind/`.pdata`, patch references, redirect the original entry, emit the PE (+optional debug map), preserving SEH/CET/CFG.

Same three stages Kamy already has — Kamy just runs step 2 as a no-op and stops short of a complete step 3.

## Section map — pre vs post protection

The two strategies are legible straight from the PE sections.

### CodeDefender — `HelloWorld.exe` → `HelloWorld-Injected.exe` (6 → 10 sections)

*Rebuilds and integrates: recycles a slot, rebuilds directories, natural `.text` entropy.*

| RVA | Pre | Post |
|---|---|---|
| `0x1000` `.text` RX | all code (CRT startup, `main`→printf) | same size, **reshuffled**: new EP init-loader stub, protected funcs trampolined, CRT startup evicted to `.belabs` |
| `0x2000` `.rdata` R | consts, IAT, `"Hello World!"` | consts + IAT **+ init-callback array** (`0x27f0–0x2800`) + LoadConfig |
| `0x3000` `.data` RW | writable globals | unchanged |
| `0x4000` **`.pdata`→`.text`** | exception table (`0x174`) | **repurposed**: renamed `.text`, made executable, holds injected helper code (fastfail/EH reporter + `memset`) |
| `0x5000` `.rsrc` R | resources | unchanged |
| `0x6000` `.reloc` R | base relocations | unchanged |
| `0x7000` **`.belabs` RX** | — | **NEW** runtime code: payload (PEB-walk + MurmurHash2 → `MessageBoxA`) + relocated CRT startup |
| `0x8000` **`.belabs` RW** | — | **NEW** runtime state + init-array bound pointers |
| `0x9000` **`.belabs` R** | — | **NEW** rebuilt **Import + Debug + Base-reloc** directories |
| `0xa000` **`.pdata` R** | — | **NEW** rebuilt/expanded exception table (`0x30c`) for relocated code |

### Kamy — `sw.exe` → `sw.prot.exe` (5 → 8 sections)

*Append-only: leaves originals untouched, duplicates the exception table, floods `.text` with int3.*

| RVA | Pre | Post |
|---|---|---|
| `0x1000` `.text` RX | 430 funcs, **ent 6.43** | 227 resident **+ 203 → `jmp` stubs + `0xCC` fill**, **ent 4.40** |
| `0x17000` `.rdata` R | consts, imports, jump tables | unchanged |
| `0x1f000` `.data` RW | writable globals | unchanged |
| `0x20000` `.pdata` R | exception table (`0xf30`) | **unchanged — left in place** (still references original RVAs) |
| `0x21000` `.reloc` R | base relocations | unchanged |
| `0x22000` **`.kamytb` R** | — | **NEW** relocation / jump-table metadata (`0xe4`) |
| `0x23000` **`.kamy` RX** | — | **NEW** 203 relocated bodies, **verbatim, plaintext** (~41 KB, ent 6.55) |
| `0x2e000` **`.kamypd` R** | — | **NEW** rebuilt exception table (RUNTIME_FUNCTIONs still point at original trampolined RVAs) |

### What the sections reveal

| | CodeDefender | Kamy |
|---|---|---|
| PE directories | rebuilt in fresh sections | left original + duplicated |
| old `.pdata` slot | recycled into code | untouched (plus new `.kamypd`) |
| `.text` after | natural entropy | `0xCC` flood (loud) |
| moved code | transformed (hash/VM) | verbatim plaintext |
| runtime RW section | yes (resolver state, init array) | none (does nothing at runtime) |

Same root cause as the rest of this doc: complete analysis lets CodeDefender **rewrite the PE's structures in place**; Kamy's cheap lift forces it to **preserve everything original and tack on** — extra sections, duplicated tables, and `0xCC` holes.
