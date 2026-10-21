# CodeDefender — how it operates

Commercial Windows PE obfuscator (Aftermath Labs, codedefender.io), x86-64 + ARM64. A **lifter-based rewriter** with a three-stage pipeline:

```
Analyze (refs/CFG/unwind, safe-reject)  →  Transform (composable passes)  →  Rebuild (native PE)
```

Marker: appended obfuscator sections (default name **`.belabs`**; rebranded builds rename them — e.g. `vgc.ac`). Observed across the samples this analysis is grounded on:

| sample | type | profile | transform enabled |
|---|---|---|---|
| `HelloWorld-Injected.exe` | EXE | light | import protection only (inject model) |
| `code_defender_crackme.bin` | EXE | heavy | mutation + MBA + control-flow indirection (+ CFG). No VM, no import protection. |
| `cheat.bin` (StealthVGC) | **DLL** | heavy | mutation + MBA + control-flow indirection (+ CFG). No VM, no import protection. Rebranded (`vgc.ac`), **selective per-function**. |

Transforms are **composable and per-build** — no sample enabled every pass, and none enabled virtualization (the vendor offers it).

## Two operation models — Transform vs Inject

CodeDefender operates in two distinct modes, and the PE layout tells them apart:

| | **Transform / Protect** | **Inject (SDK model)** |
|---|---|---|
| intent | harden *existing* code | add *new* functionality to a compiled PE |
| sample | `code_defender_crackme.bin` | `HelloWorld-Injected.exe` |
| what it does | rewrite original functions (mutation/MBA/VM), semantics preserved | bolt on new behavior (here: a hash-resolved `MessageBox`) run before the original entry |
| EP hijack | inline `call payload; jmp orig_start` | **init-callback array** `[payload, original_start]` walked by a loader |
| runtime-state `.belabs` (RW) | **none** — no new behavior to register | **yes** — holds the init-callback registry/bounds |
| new dependencies | none | resolved at runtime (PEB-walk + MurmurHash2), **no new IAT entry** |

The RW runtime-state `.belabs` is therefore a **signature of the inject model**, not of transformation. In the Injected sample the payload (`sub_140007000`) builds `"user32.dll"`/`"Hello World!"` on the stack, walks `Ldr->InLoadOrderModuleList`, hashes module + export names with MurmurHash2 (`0x5BD1E995`), resolves `MessageBoxA`, and calls it — `user32.dll` never appears in the import table. That injected code is wired in through the init array, which is exactly what the RW section exists to hold.

**Correction (third sample, `cheat.bin`):** an RW obfuscator section is **not** exclusive to the inject model. The transform-only `cheat.bin` also ships an RW `vgc.ac`, but it holds a **single pre-initialized code pointer** (read once at init, `mov rax, cs:off_…; mov [r8+0F8h], rax`) — not an init-callback `[begin,end)` registry. So RW *presence* alone does not imply inject; the discriminator is the **init-callback array + loader loop** (begin/end bounds over `[payload, original_start]`), which only the inject build has.

---

## 1. Analyze
Recovers function boundaries, control flow, references, and unwind metadata (optional PDB), and **reports functions it cannot transform safely** (safe-reject). This complete reference model is the enabler for everything downstream: it is what lets Rebuild relocate code freely and rewrite every reference.

## 2. Transform (catalog)
Composable per-function passes:
- **Mutation + MBA + loop-encoding** — rewrite instructions into Mixed-Boolean-Arithmetic identities, magic-constant arithmetic, flag/bit junk.
- **Control-flow** — opaque predicates, indirect branches, block duplication, reference hiding.
- **Constant hardening + import protection** — hash-resolved API calls (PEB walk + MurmurHash2), hidden constants.
- **Code virtualization** — key-driven handlers, isolated VM state (not seen in either sample).
- **SigBreaker** — binary diversification (instruction reorder, block shuffle).

## 3. Rebuild
Emits a **native** PE (optional debug map), preserving SEH/C++ EH, compatible with CET/CFG/ACG. Two properties matter most:

### 3a. Relocation rebasing (reference rewriting)
CodeDefender does **not** leave a thunk per moved function (that is Kamy's address-preserving model). It rewrites references to the moved VA so callers point directly at relocated code. Measured on the crackme:

- **953** intra-`.belabs` direct `call`/`jmp` resolve straight to moved VAs (rel32).
- **26** base relocations in the whole image, **0** into `.belabs` → relocated code is fully **position-independent** (rel32 + rip-relative addressing, no fixups).
- Only **10** residual `.text`→`.belabs` stubs remain, and **every one** is forced by a `.pdata` `RUNTIME_FUNCTION` (unwind) reference — not by the move itself.

Reference classes rewritten during Rebuild:

| class | fix |
|---|---|
| direct `call`/`jmp` rel32 | recompute displacement to new VA *(bulk; no `.reloc`)* |
| rip-relative data | recompute disp32 *(no `.reloc`)* |
| absolute pointers (`.reloc`) | rebase to new VA *(minor in x64)* |
| jump tables / switch | **no table survives** — switch lowered to a compare ladder + computed `jmp rcx` through `jmp rel32` pads (see *Switch / jump-table handling*) |
| `.pdata`/`.xdata` unwind | regenerate at new func RVAs |
| export / TLS / debug / loadcfg | new RVAs |

### 3b. Reusability — section-slot recycling + directory rebuild
Because Rebuild regenerates the whole image, CodeDefender **recycles existing section slots and rebuilds PE directories into fresh sections** instead of only appending:

- The original `.pdata` slot is **repurposed** — renamed `.text`, made executable, filled with injected helper code (fastfail/EH reporter, `memset`).
- **Import / Debug / Base-reloc directories are rebuilt** into appended `.belabs` sections; a fresh `.pdata` is emitted for the relocated code.
- EP is **hijacked** to a payload-then-original sequence (see §4).

This is the opposite of an append-only protector (e.g. Kamy), which leaves every original structure in place and duplicates tables — producing extra sections and stale directories.

### 3c. `.text` resizing — why the rebuilt `.text` stays compact and natural
A complete, rebaseable reference model is also what lets CodeDefender keep `.text` **short with natural entropy** (no `0xCC` flood):

- Every reference is rebased, so moved code can live entirely in `.belabs` and the `.text` that remains is real code (EP, dispatchers, the few unwind stubs), not a swiss-cheese of trampolines + int3 fill.
- An append-only, address-preserving rewrite **cannot** shrink `.text`: moved functions leave interleaved holes at their original RVAs, so `.text` must stay full-size with `jmp` stubs and `0xCC` padding (entropy collapses, signature loud). Shrinking `VirtualSize`/`SizeOfRawData` only removes a contiguous dead tail — live code sits past the holes.
- "Can't compact `.text`" and "no protection" are the **same** missing capability: the complete reference model is the prerequisite for *both* a clean/compact rebuild and for inserting transforms.

---

## Entrypoint handling

CodeDefender hides the original entrypoint by **redirecting** it, not by TLS or header tricks. `AddressOfEntryPoint` stays a valid pointer — into `.text` for the EXE/EFI samples (landing on a loader stub), or **directly into the appended code section** for the DLL sample (landing on the moved+mutated original entry). The code reached runs a payload first and/or is the relocated entry itself — so the real entry is no longer at a recognizable `.text` OEP.

| mechanic | sample | effect |
|---|---|---|
| EP → `.belabs` payload stub | crackme, `bootmgfw.efi` | EP stub `…; call <.belabs payload>; jmp rbx` — original OEP displaced, reached indirectly |
| init-callback array | HelloWorld-Injected | EP → loader loop over `[payload, original_start]`; the real entry is an anonymous array element reached by computed iteration (strongest form) |
| control-flow indirection at EP | crackme, `bootmgfw.efi` | stub uses the `jmp` / `call;jmp reg` continuation idiom — tracing from the EP is obfuscated |
| section-name blanking around EP | `ntoskrnl2.exe` | the section holding the EP has its **name zeroed** — breaks section-name EP heuristics |
| EP → appended-section entry (DLL) | `cheat.bin` | `AddressOfEntryPoint` points *into* the obfuscator code section at the moved+mutated `_DllMainCRTStartup`; no `.text` trampoline fronts it. The `call <body>; jmp rbx` stub still exists in `.text` but is demoted to a residual/internal path |

Evidence: `bootmgfw.efi` EP = `push rbx; sub rsp,0x20; jmp 0xa2ce3; call .belabs:0x10ba366` (payload), then `jmp rbx`.

Evidence (`cheat.bin`, DLL): EP RVA `0x10b003e` is inside the appended `vgc.ac` code section and `jmp`s straight into the 381 KB MBA `_DllMainCRTStartup` body (`rcx`/`rdx`/`r8` = hinst/reason/reserved spilled, `reason==1` test, single `ret`). **Why no `.text` stub:** an EXE entry (`mainCRTStartup`) is fire-and-forget (`ExitProcess`), so CD fronts it with a `call payload; jmp orig` trampoline; a DLL entry is a *returnable* `DllMain`, so CD just repoints `AddressOfEntryPoint` at the relocated entry and lets it `ret` to the loader — nothing to sequence. The enabling condition is a **transform-only** build: no injected pre-entry payload to run first (the RW section holds a lone pointer, not an init array).

**Not used (these samples):** no **TLS callbacks** (TLS directory absent in all research binaries, `cheat.bin` included); no `AddressOfEntryPoint=0` / forwarder trick.

**Not universal — target-dependent:** `ntoskrnl2.exe` (protected kernel) keeps its EP **byte-identical** to clean `ntoskrnl.exe` — `KiSystemStartup` is *not* hijacked; internal functions are protected and the OEP is left intact. EP redirection is applied to the usermode crackme and the boot manager, skipped for the kernel entry.

**Takeaway:** EP hiding here = redirect to run a payload first + displace the OEP (buried in a callback array in the inject profile). It is **discoverable** (follow the stub / the array), not cryptographically hidden.

## Observed runtime shape (crackme, heavy profile)

**EP hijack:** `start` → `call` a 78 KB `.belabs` payload (`sub_1400B725D`, itself MBA-mutated, builds a ~4 KB stack state frame) → `jmp` the original CRT start. Confirmed live in x64dbg: the payload's return address is the instruction right after the EP `call`.

**Transform = mutation, not VM:**
- The only indirect jump in 6.4 MB of `.belabs` is `jmp cs:__guard_dispatch_icall_fptr` (Control Flow Guard). No dispatcher, no handler table → **no virtualization**.
- Giant mutated bodies: the largest is **369,650 instructions across 371 basic blocks with 1 `ret`** — near-straight-line native code. 32 functions exceed 64 KB. Instruction mix is MBA/junk: `mov`, `or`/`and`/`xor`, `ror`/`bswap`, `lahf`/`sahf` (flag obfuscation), `cmov*` (branchless), magic-constant `mul`.
- **State smearing:** intermediates spill across a 64 KB+ stack frame, shuffled in 16-byte chunks by tiny `movdqa` helpers — the real analysis cost.
- **Control-flow indirection:** `main` keeps 24 `call <block>` slots in `.text`; 23 are followed by `jmp rcx` (the last falls into the epilogue). Each block computes the next continuation into `rcx` and jumps indirect, defeating static CFG recovery. Switches are lowered onto the same mechanism (next section).

**No import protection:** IAT fully intact — 45 plain imports (CRT + 15 KERNEL32), no hash resolver.

## Register model — spill-everything lowering (why megabyte bodies never blow up regalloc)

The giant MBA bodies never hit register pressure because CodeDefender does **not** color an unbounded virtual-register graph over the function. It lowers to a fixed 15-GPR machine and treats a large stack frame as the register file. Pressure is capped *by construction*: the transform pre-spills every intermediate to memory, so the live set at any point ≈ one instruction's arity. Measured on the largest body `sub_1404C1C06` (1.79 MB, ~369k insns):

| metric | value | meaning |
|---|---|---|
| frame size | **0x10708 = 67,336 B** | ~8,400 qword / 4,200 xmm spill slots |
| distinct `[rsp+disp]` slots (60k-insn sample) | **1,096** | memory-backed register file, not a few locals |
| stack-relative share of all mem operands | **95.5%** | nearly every memory touch is a spill/reload |
| `mov` share (40k-insn window) | **44%** (17,709) | body is mostly load-slot / store-slot traffic |
| max simultaneously-live GPRs (backward liveness, 8k window) | **16; median 8–10** | saturates the HW file, **never exceeds it** |
| `rsp` as scratch reg | **0** | RSP is only the frame base |
| `rbp` as scratch reg | **459** | **no frame pointer — RBP is a normal allocatable GPR** |
| `lahf`/`sahf` (40k window) | **749 / 749** | flags snapshotted to a stack byte, not kept live |

Every MBA step is a load→compute→store triple against frame slots:
```
mov    r9, [rsp+...var_A148]     ; load virtual-reg from frame slot
popcnt r8w, r9w                  ; 1-3 ALU ops on scratch GPRs
mov    [rsp+...var_A120], rcx    ; store result back to a frame slot
```
Flags are never a long-lived value — materialized into `ah` and folded into a stack byte, reloaded on demand (`lahf; and ah,3Fh; or ah,byte ptr [rsp+...var_9D4C]; … sahf`).

**Four design choices that make pressure non-fatal:**
1. **Memory is the register file.** Between uses, values live in frame slots; only ~2–3 are resident. 1,096 virtual regs coexist with zero pressure.
2. **The transform pre-spills.** MBA identities are emitted as load/compute/store triples, so regalloc only ever sees a local live window — spilling is rarely even needed.
3. **Flags are memory-backed.** Snapshot to a byte at each def, reload at each use → no long-range EFLAGS interference (a classic lifter pressure bomb).
4. **No frame pointer.** RSP-relative addressing with a big constant frees RBP → 15 allocatable GPRs, no ABI pin.

**Implication for an append-only lifter (Kamy):** a `RegisterPressure` *failure* at lower time means spill is an error path, not a fallback. CD's invariant is that pressure is never fatal — the stack is infinite. Make unbounded spill-slot allocation the default (grow the frame), emit transformed expressions in near-spilled memory-form, model flags as memory-backed state, and drop the frame pointer. Then a 369k-instruction body colors as easily as a 10-instruction one.

## Switch / jump-table handling (crackme)

CodeDefender does **not** rewrite jump-table entries — it **removes the table**. The switch is lifted into the CFG and re-emitted as a linear compare ladder; every edge, including each case edge, goes through a computed `jmp rcx` to an unreferenced `jmp rel32` pad. Nothing in the image is indexed by the switch value.

### Static evidence — no table anywhere
- IDA `get_switch_info` returns nothing anywhere in the image.
- No MSVC x64 switch idiom (`lea rdx, __ImageBase; mov ecx, [rdx+rax*4+tbl]; add rcx, rdx; jmp rcx`). The only `lea …, __ImageBase` (`0x140001AF5`) is the CRT `MZ`/`PE` header check.
- Scanning every section for ≥3 consecutive dword RVAs / qword VAs into executable code finds only reloc'd CRT pointers (`0x1400031A0`), `__C_specific_handler` scope tables (`0x140006158`) and `.xdata` unwind codes. No jump table.
- Register-indirect `jmp` in executable code: 23 × `jmp rcx` in `main` (`sub_140001BF5`), `jmp rbx` (EP, `0x140001E6D`), `jmp rax` (CFG nop thunk). Zero in `.belabs`.

### Mechanism: block → selector `cmov` → pad → slot
```
main (.text, sub_140001BF5)              .belabs block (sub_1402CCF80, ~45k insns)
140001c47: call sub_1402CCF80  ───────►   … MBA …
140001c4c: jmp  rcx                        lahf/and/or/sahf      ; restore spilled CF/ZF
140001c4e: … call sub_1402623CC            cmovnz rcx, [rsp+60h] ; pick 1 of 2 pad VAs
140001c65: jmp  rcx                        … ret
140001c67: call sub_140330BF7   ◄── pad 14000101A: jmp loc_140001C67
140001c6c: jmp  rcx
…  (7-byte call/jmp slots)  …
140001cfa: call sub_1403DC5EB ; add rsp,38h ; ret
```
- **Slot** = `call <block>; jmp rcx` in the original function, which stays in `.text`. **Block** = an outlined, MBA-mutated `.belabs` function (14k–60k insns, one `ret`).
- **2-way blocks** end with `cmov<cc> rcx, <alt pad>`; flags are rebuilt from a spilled byte via `lahf`/`sahf` immediately before it. **1-way blocks** have no selector (only the `cmovo cx, ax` flag junk).
- **Pad table** `0x14000101A`–`0x1400010A1` in `.text`: 24 `jmp rel32` stubs, one per branch-target slot. **Zero xrefs** — no reloc, no data, no direct code ref. Reachable only through the computed `rcx`. (`0x140001015` is a `.pdata`-forced unwind stub, not a pad.)
- The pad VA is materialized arithmetically (e.g. `mul rdx; lea rdx, [rax+rcx]`), sometimes off a decoy anchor (`lea rdx, loc_14000103D+2` in `sub_1402CCF80`). No relocation is needed, so it stays PIC.

### The recovered switch
Traced live in x64dbg. Breakpoints on each selector `cmov` read both candidates (`rcx` = else, cmov source = if), and the pad's `rel32` maps it to a slot. Inputs were of length 1–9, 16 and 40.

`main` walks `argv[1]` with an 8-byte block loop (`C60`/`C67`/`C6E`, runs ⌊len/8⌋ times), then runs a **switch on `len & 7`** lowered as a descending `≥` ladder (`cmovnb` = unsigned ≥):

| slot | block | test | taken → | else → |
|---|---|---|---|---|
| `C7C` | `sub_140285391` | rem ≥ 7 | `C83` case 7 | `C8A` |
| `C8A` | `sub_14021E0D1` | rem ≥ 6 | `C91` case 6 | `C98` |
| `C98` | `sub_14019DABC` | rem ≥ 5 | `C9F` case 5 | `CA6` |
| `CA6` | `sub_1401DD312` | rem ≥ 4 | `CAD` case 4 | `CB4` |
| `CB4` | `sub_1402A8D03` | rem ≥ 3 | `CBB` case 3 | `CC2` |
| `CC2` | `sub_1401BD48F` | rem ≥ 2 | `CC9` case 2 | `CD0` |
| `CD0` | `sub_1401424DC` | rem ≥ 1 | `CD7` case 1 | `CDE` default (rem 0) |

Case bodies `C83` `sub_14017E38E`, `C91` `sub_1401286A5`, `C9F` `sub_14010F563`, `CAD` `sub_140053643`, `CBB` `sub_1400F7528`, `CC9` `sub_1400945F5` each jump **directly** to `CD7` (`sub_14007365B`, case 1), which continues to `CDE`. They do not chain 7→6→…→1. *Inference:* the source is a Murmur-style fall-through tail, and each case body carries its own copy of the lower cases' work (tail duplication). The protector's block duplication and the compiler are both plausible causes; telling them apart needs the unprotected build.

Exact traces (slots visited after the block loop):
```
rem 0: c7c c8a c98 ca6 cb4 cc2 cd0 cde …
rem 1: c7c c8a c98 ca6 cb4 cc2 cd0 cd7 cde …
rem 2: c7c c8a c98 ca6 cb4 cc2 cc9 cd7 cde …
rem 3: c7c c8a c98 ca6 cb4 cbb cd7 cde …
rem 7: c7c c83 cd7 cde …
```

### How to recover switches without a table
1. Find the slots: `call X; jmp rcx` pairs in the surviving `.text` function.
2. In each block, take the last `cmov<cc> rcx, …` before `ret`. Breakpoint it and read `rcx` plus the source operand to get **both** successors without simplifying the MBA. Blocks with no such cmov are unconditional.
3. Resolve pad → slot by decoding the pad's `E9 rel32`.
4. A run of 2-way blocks with one side exit each, tested in monotonic order, is a lowered switch. The case value is the ladder position, and the last block's fall-through is `default`.
5. To restore IDA's graph, add `fl_JN` crefs from each `jmp rcx` to its resolved slots (`idc.add_cref`).

### Cross-build check: `ntoskrnl.exe` vs `ntoskrnl2.exe` (kernel, same CD)

The crackme left the open question of whether a large/sparse switch becomes a ladder, a tree, or a rewritten table. Comparing the clean kernel against the CD-rebuilt kernel answers part of it and corrects a wrong assumption: **on the kernel, CD is applied selectively, not whole-image.** Both IDBs saved (`research_bin/ntoskrnl.exe.i64`, `ntoskrnl2.exe.i64`).

- Clean `ntoskrnl.exe` has full PDB symbols and **52** IDA-recovered table-based switches (4 are `2-4` cases, 23 are `17-64`, 7 are `65+`; **15** are sparse two-level `SWI_INDIRECT` value+index tables). All use the stock MSVC rel32 idiom `lea rX, __ImageBase; mov eY,[rX+idx*4+tbl]; add; jmp rX`.
- Rebuilt `ntoskrnl2.exe` has **no PDB** (export names only; match by RVA, which is layout-stable) and still recovers **51** switches — **at identical RVAs, identical sections, identical MSVC idiom**. CD appended a second `.text` (`0x377000`) + two `.belabs` sections and rewrote only **~12 functions** (residual `E9 rel32` `jmp` stub at the original RVA → relocated MBA body); **>99.9% of ~16.9k functions are byte-identical** to clean. The EP-byte-identical observation (§ Entrypoint handling) is the same story: this build protects a handful of functions, not the image.
- **Exactly one** switch disappeared: `NtQuerySystemInformation` (`sub` switch `0x482C9C`, nc134 → 4 distinct targets). Its function was one of the ~12 rewritten: original RVA `0x482C40` now holds `jmp sub_140818DAC`, body relocated to INIT tail `0x818DAC`. The 134-entry index table + rel32 jump table are **gone**; the body is a short chain of `call <block>; jmp rdx` slots whose blocks select the successor with `cmovp`/`cmovz` after `lahf`/`sahf` flag restore — the **same computed-slot/`cmov` scheme as the crackme**, target VA produced by MBA, not a table index.
- Every other candidate — including the large/sparse ones `ExpQuerySystemInformation` (nc176, nc174 two-level), `NtSetInformationProcess` (nc71), `BuildQueryDirectoryIrp` (nc62), `PipIsProblemReadonly` (nc54), `SeSetAuditParameter`/`_MapCmDevicePropertyToRegType` (two-level) — **keeps its original jump table verbatim**, because CD did not touch those functions.

**Answer (partial):** CD does **not** convert surviving switches to ladders or trees — an untouched switch keeps its table. When CD *does* rewrite a switch-bearing function, the table (dense or sparse index) is **eliminated** in favor of the computed-slot/`cmov` dispatch, **not** rebuilt as a table and **not** expanded into a full linear ladder over every case value. **Still open:** only one rewritten switch is observable in these two samples (sparse, 4 targets). Whether a large *dense* switch would lower to a linear `cmov` chain (as the crackme's 8-way `len&7` did) or to a bisection tree is still untested — it needs a build where CD rewrites a dense-switch function.

## Security structures — /GS, CFG, segments, CRT (crackme)

CodeDefender's Rebuild relocates **real instructions byte-faithfully** and rewrites every dependent structure to match the new layout, so the moved `.belabs` code keeps valid stack cookies, CFG metadata, segment semantics, and CRT teardown. Verified live in `code_defender_crackme.bin`.

### Segments — overrides preserved verbatim
Relocated `.belabs` code still carries native segment-override instructions, e.g. `0x1400092a7: mov rax, gs:30h` (TEB self-pointer). Relocation re-encodes the instruction with its `0x65` GS prefix intact, so the CPU/OS resolve the segment base at runtime unchanged. CodeDefender never needs a flat-address model: `gs:`/`fs:` accesses (TEB/PEB, TLS, stack-cookie seed) survive the move with no rewriting.

### /GS stack cookie — routine relocated, global pinned, reference rebased
`__security_check_cookie` is itself relocated into `.belabs` (`0x14000904e`):
```
cmp  rcx, cs:__security_cookie   ; rip-rel to the global, still resolves to 0x140005000
jnz  fail
rol  rcx, 10h
test cx, 0FFFFh
jnz  short ...
ret
fail: jmp __report_gsfailure     ; 0x14000136c, left in .text
```
- The cookie **global** `__security_cookie` stays in `.data` at its original VA (`0x140005000`); the moved check function's rip-relative reference to it was rebased so it still resolves there.
- `__report_gsfailure` (`0x14000136c`) and the per-function prologue/epilogue cookie framing (`xor rax, rsp` stamp then epilogue check) are preserved, because relocation keeps the exact stack layout and rebuilds unwind — the compare matches, no fast-fail.

### CFG / LoadConfig — rewritten into a consistent state
LoadConfig (`_load_config_used`, `0x140006000`, Size `0x140`) after protection:

| field | value | meaning |
|---|---|---|
| `SecurityCookie` | `0x140005000` | points at the untouched `.data` cookie |
| `GuardCFCheckFunctionPointer` | `0x1400031a0` | → `_guard_check_icall_nop` |
| `GuardCFDispatchFunctionPointer` | `0x1400031b0` | → `_guard_dispatch_icall_nop` (`jmp rax`) |
| `GuardCFFunctionTable` | `0x140003518`, count **1** | lone target `0x140001e27` (valid, in `.text`) |
| `GuardFlags` | `0x100` | `CF_INSTRUMENTED` only — **`CF_FUNCTION_TABLE_PRESENT` (0x400) not set** |

- Both CF fptr slots resolve to the **nop** thunks (`_guard_dispatch_icall_nop` = `jmp rax`, no bitmap lookup), so an indirect call through `jmp cs:__guard_dispatch_icall_fptr` does not validate its target against a table.
- The guard function table is kept **minimal and internally valid** (1 entry pointing at live `.text`), and `GuardFlags` omits `FUNCTION_TABLE_PRESENT` — the metadata never contradicts the relocated layout. The only indirect jump in 6.4 MB of `.belabs` is `jmp cs:__guard_dispatch_icall_fptr`.
- Net: CodeDefender ships a CFG-aware image whose LoadConfig is rewritten to a non-enforcing, consistent state rather than left describing the pre-move layout.

### CRT — relocated verbatim, tables stay correct
The full CRT startup/teardown machinery is present and consistent: `_initterm`/`_initterm_e` (`0x14000218c`/`0x140002192`), `_register_onexit_function` (`0x1400021e0`), `_crt_atexit` (`0x1400021e6`), `_initialize_onexit_table` (`0x1400021da`), `_register_thread_local_exe_atexit_callback` (`0x1400021c2`). CRT startup is relocated as faithful bytes (EP → `.belabs` payload → `jmp` original CRT start). Because the init/onexit routines are copied rather than recompiled, the function pointers they materialize and store into the initterm/onexit/terminator tables are correct VAs, so the teardown walk runs cleanly.

### Takeaway
A complete, rebaseable reference model plus byte-faithful relocation keeps these structures valid: code moves without changing instruction semantics (segments and cookie framing survive), the cookie global is pinned while its rip-relative references are rebased, and the CFG/LoadConfig directory is rewritten to a consistent non-enforcing state instead of left stale.

## Observed section maps

### crackme — `code_defender_crackme.bin`
| VA | section | flags | serves |
|---|---|---|---|
| `0x1000` | `.text` | R-X | EP hijack, dispatchers, 10 unwind stubs (8 KB) |
| `0x3000`–`0x8000` | `.idata`/`.rdata`/`.data`/`.rsrc` | R/RW | imports, consts, verdict pointer pair, resources |
| `0x9000` | **`.belabs`** | R-X | **6.7 MB** relocated+mutated bodies (PIC) |
| `0x677000` | `.pdata` | R | regenerated unwind table |
| `0x678000` | **`.belabs`** | R | **`.xdata`** unwind for relocated code (123 `.pdata` xrefs, no code refs) |

### HelloWorld-Injected — three `.belabs` (light / import-protection profile)
| VA | section | flags | serves |
|---|---|---|---|
| `0x1000` | `.text` | R-X | EP-hijack loader (`start`) + stubs |
| `0x4000` | **`.text`** | R-X | old `.pdata` slot **repurposed** to code (fastfail/EH reporter, `memset`) |
| `0x7000` | **`.belabs`** | R-X | payload (PEB-walk + MurmurHash2 → `MessageBoxA`) + relocated CRT startup |
| `0x8000` | **`.belabs`** | **RW** | **runtime state** — init-array bounds + ~4 KB zero scratch |
| `0x9000` | **`.belabs`** | R | rebuilt Import / Debug / Base-reloc directories |
| `0xa000` | `.pdata` | R | regenerated unwind table |

Payload resolves `user32!MessageBoxA` via PEB `InLoadOrderModuleList` + MurmurHash2 (`0x5BD1E995`) — no IAT landmark.

### cheat.bin (StealthVGC) — DLL, transform-only, rebranded `vgc.ac`
| VA | section | flags | serves |
|---|---|---|---|
| `0x1000` | `.text` | R-X | **903** surviving functions (811 real + 76 tiny + 16 residual→code stubs), 244 KB — selective transform, `.text` **not** vacated |
| `0x3d000`–`0x60000` | `.idata`/`.rdata`/`.data`/`.rsrc` | R/RW | IAT (104 imports, intact), consts, resources |
| `0x61000` | **`vgc.ac`** | R-- | rebuilt **Base-reloc** directory |
| `0x64000` | **`vgc.ac`** | **RW** | **runtime state** — a *single* pre-init code pointer (not an init array) |
| `0x65000` | **`vgc.ac`** | R-X | **17.7 MB** relocated+mutated PIC code (2942 funcs, incl. the EP/`DllMain` body) |
| `0x114b000` | `.pdata` | R | regenerated unwind (5120 `RUNTIME_FUNCTION`s) |
| `0x115a000` | **`vgc.ac`** | R | **`.xdata`** unwind for relocated code |

Four `vgc.ac` sections (R-- dirs, RW state, R-X code, R `.xdata`); the EP lands in the R-X one. IAT fully intact (KERNEL32 89 / USER32 9 / WININET 6, no hash resolver); relocations 931 total, only **1** into the code section (PIC); CFG non-enforcing (`GuardFlags=0x100`, dispatch→nop thunk) — same consistent-but-neutered state as the crackme. Only **1** residual jump-table switch survives; no VM dispatcher (895 `jmp reg` + 2086 `call reg` are the computed-continuation idiom, spread across registers, with a lone `__guard_dispatch_icall_fptr`). Confirmed CodeDefender via forged CodeView (`RSDS`, Age 3, name `"Protected by StealthVGC"`, not a `.pdb`).

> **Obfuscator-section layout is per-build, not fixed — 2 to 4 sections observed, and the name may be rebranded (`.belabs` default, `vgc.ac` in `cheat.bin`).** Roles seen: **R-X** relocated code (always); **RW** runtime state (inject *or* transform); **R** rebuilt directories *and/or* `.xdata`. Crackme = 2 (R-X code + R `.xdata`); Injected = 3 (adds RW state + R directories); `cheat.bin` = 4 (R dirs + RW state + R-X code + R `.xdata`). Do not assume a fixed count, a fixed name, or that an RW section implies the inject model.

#### How the RW runtime-state `.belabs` works
It is a **CRT-style initializer table** (`_initterm_e` shape), not a scratch heap. The RW `.belabs` stores the bounds of a startup callback array:

```
.belabs:8000  begin = 0x1400027f0
.belabs:8008  end   = 0x140002800
array (.rdata): [0x27f0] = payload  sub_140007000
                [0x27f8] = original CRT start  sub_140001497
.belabs:8010  … ~4 KB zero scratch (reserved; unwritten in the static image)
```

The hijacked EP (`start` = `sub_14000152d`) walks `[begin,end)` calling each `callback(argc,argv,envp)`; a nonzero return triggers `__fastfail` (`int 29h`). The **payload runs first** (shows the MessageBox); the **final callback is the original CRT start**, which runs the program and exits — so control never returns to the loader. The bounds sit in a *writable* section because CodeDefender models them like the MSVC CRT initializer iterators (`__xi_a`/`__xi_z`). The crackme has no equivalent: it hijacks the EP inline (`sub rsp; call payload; jmp orig_start`) with no array, loader, or writable state.

`cheat.bin` sits between the two: transform-only (no init array, like the crackme) yet still shipping an RW `vgc.ac` — but holding just **one** pre-initialized code pointer, read once and stored into a runtime struct field (`mov [r8+0F8h], rax`), not a `[begin,end)` iterator. So the RW section's *presence* does not distinguish the models; its *shape* (lone pointer vs begin/end bounds + loader loop) does.

---

## Reversing notes
- **Markers:** appended obfuscator section(s) — name `.belabs` or rebranded (`vgc.ac`); forged CodeView debug entry (`RSDS`, Age 3, non-`.pdb` name, e.g. `"Protected by StealthVGC"`); EP = `.text` `sub rsp; call <code sec>; jmp <orig start>` (EXE/EFI) **or** `AddressOfEntryPoint` pointing straight into the code section at a mutated `DllMain` (DLL); `.pdata`-only residual `.text` stubs.
- **Weaknesses (as configured in these samples):** everything is **native** — no VM bytecode to lift. Mutation is MBA, mechanically simplifiable to identities; the heavy profile is tedious (state smeared across a large stack frame, indirect continuations) but not opaque. Light profiles leave the IAT fully visible.
- **Strengths:** complete rebuild (clean/compact `.text`, rebuilt directories, valid SEH/CFG), composable transforms, and — where enabled — hash-resolved imports that erase IAT landmarks.
