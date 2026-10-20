# Corpus SSA-identity crash — RCA handoff (#24)

## 1. What was audited

The runnable differential corpus was expanded to 22 members (12 console, 8 dll,
gui_msgbox, vendored kernel32) and compiled+blessed (each has
`orig/<name>.{exe,dll}` + `expected.yml`). The `kamy-corpus` build driver gained
`link_flags` support (per-member linker flags: `/guard:cf`, `/LTCG`). clang-cl
members: dll_adx (`-mbmi2 -madx`), dll_asm (GNU inline asm), dll_bmi1 (`-mbmi`).

`kamy corpus verify` runs the SSA-identity backend (`protect_with_transforms` +
identity transform) over each member and diffs runtime behavior vs the blessed
golden.

Result: **2/22 PASS** (console_fibmix [rustc], kernel32 [prebuilt]); **20 FAIL**.

## 2. Root cause (PROVEN) — issue #24

Every one of the 20 FAILs is the same hard crash: exit `-1073741819` =
`0xC0000005` ACCESS_VIOLATION. DLL members report `<loader-failed exit
-1073741819>` on every export (the crash happens at DLL load, before any export
runs).

Faulting instruction, byte-identical across members: `448A18` =
`mov r11b, byte ptr [rax]`, inside a `strnlen(ptr, 256)`-shaped loop:
load byte -> `test r11b,r11b` -> `setz al; mov r11b,al; xor r11b,1` (the BoolNot
negation from the #23 fix) -> loop; the limit 256 lives in rbx/rdx/rdi.

Registers at fault: `rax=0xFFFFFFFFFFFFFF02`, `rcx=0xFFFFFFFFFFFFFF01`,
`r9=0xFFFFFFFFFFFFFF00`. The loop-invariant base pointer was dropped to ~0 on
the loop back-edge; only the index survives, so iteration 2 dereferences a
near-zero garbage pointer -> AV. This is exactly issue #24's signature (loop
header phi takes `Undef` on the back-edge argument).

Location: a shared **MSVC `/MT` static-CRT startup** routine, executed before
`main`/exports. That is why ALL compiled members (msvc AND clang-cl, which both
link the MSVC CRT) crash identically; rustc `console_fibmix` and prebuilt
`kernel32` use a different/clean path and PASS.

Dynamic proof (x64dbg), 4 structurally-diverse members, all identical fault
bytes + registers:

| member | crash context | fault RVA in protected image |
|---|---|---|
| console_sse | exe startup | +0x2A530 |
| console_tls | exe startup | +0x2A530 |
| dll_abi | DLL init via LoadLibrary | +0x640 |
| dll_asm (clang-cl) | DLL init | +0x2DB0 |

(The RVA differs per binary layout; the instruction bytes and the garbage
register values are identical.)

## 3. Residual risk AFTER #24 (static IDA of the protected PEs)

- BMI/ADX single-op intrinsic exports: lowered via NativeInline and CORRECT,
  e.g. `bmi1_bextr_0` = `mov rax,0x804; bextr rax,rcx,rax; ret`. Expected to
  PASS post-#24.
- dll_atomic exports: REJECTED in-place (`lock cmpxchg`/`xadd` kept as original
  bytes) -> safe post-#24.
- SEH / switch / TLS / SSE functions: REJECTED (reasons SEHComplex /
  BadIndirectBranch / UnsupportedInstruction) -> safe but uncovered.
- dll_asm: `asm_mix` is fully unrolled and clean; `asm_adc_0` is SUSPECT for
  issue #8 (NativeInline operands not pinned) — it reuses `rdx` (still holding
  input `b`) as the carry-capture destination where the source zeroes that
  register first. Verify after #24.
- IMPORTANT caveat: the crash is EARLY in CRT init. Fixing #24 may expose a
  SECOND lowered loop with the same back-edge bug further along startup. Do not
  assume 20 -> PASS; re-run `kamy corpus verify` after the #24 fix.

## 4. How to reproduce

The SSA-identity protected image is produced by
`protect_with_transforms(&pe, &module, &funcs, &Options::default(),
&Win64Default, &mut identity)` where `identity = |_,_|{}` — see
`protect_ssa_identity` in `crates/kamy-cli/src/main.rs`. It is only wired into
`corpus verify`; to emit a standalone protected PE for inspection, add a
~15-line `cargo` example that calls it and `std::fs::write`s the image.

Write protected outputs under `<corpus>/protected/` (AV-excluded). Elsewhere
Microsoft Defender quarantines them on write (file write fails / err 225).

Console: load the protected exe in x64dbg, continue twice -> AV. DLL:
`debug_init` x64dbg on `kamy-loader.exe` with arguments
`"<protected.dll>" <export> <retkind> <argtoken...>` (e.g.
`abi_small i32 i32:5 i32:9`), continue 3x -> AV during DLL init.

## 5. Linked issues

- Primary (the crash): **#24** (bug) — SSA construction drops a loop-invariant
  reg on the loop back-edge. Fix sketch is in the issue.
- Secondary (surfaces after #24): **#8** (bug) — NativeInline register operands
  not pinned; relevant to dll_asm (multi-register inline asm).
- Coverage debt (NOT a FAIL cause; these constructs are rejected and run as
  original bytes): #11 (model SSE/x87/atomics/BMI as SSA ops), #12 (SEH
  reconstruction), #21 (jump tables), #25 (recover reject-cost coverage), #26
  (fs/gs via NativeInline).
- #23 is the umbrella bug tracker; it closes when #24 lands.

## 6. Resolution (2026-10-20)

#24 landed as **two** backend fixes; corpus 2/22 → **11/22**.

1. **SSA back-edge phi threading** (`kamy-lift/src/ssa.rs`). Placeholder
   resolution rewrote only the resolving block, so an already-created loop-header
   phi in a different block kept the body's `Undef` back-edge arg. Resolution now
   threads the arg across all blocks. This was the exact AV in §2 (loop-invariant
   base pointer dropped to ~0). Flipped `gui_msgbox`.
2. **Linear-scan loop liveness** (`kamy-codegen/src/regalloc.rs`). Live ranges
   were the *syntactic* last use over a DFS block order; a value live across a
   loop back-edge was freed early and its register reused mid-loop. This is the
   "second lowered loop" §3 warned about — it surfaced not as another AV but as a
   miscompile of the ucrt `write_integer` hex nibble loop (`%#018llx` garbled,
   float fields correct). Liveness is now a real backward SSA dataflow to a
   fixpoint; each interval is the convex hull of all live points. Cleared every
   plain console member.

Both carry regression tests. Remaining **11 FAIL**, two further distinct
miscompiles the #24 fix unmasked:

- **8 `dll_*`**: exports return correct values, then AV (`0xC0000005`) at
  DLL/process teardown. The crashing routine (a 16-byte-stride onexit/terminator
  table walk dispatched through the CFG `_guard_dispatch_icall` thunk) is
  relocated verbatim and correct; it loads a **garbage callback pointer** from the
  table, so a lowered CRT-*init* function stored a bad pointer during attach.
  Pointer-materialization bug, not liveness. Next target.
- **3 console** (`console_cfg`, `console_cfg_lto`, `console_eh`): `0xC0000409`
  (STATUS_STACK_BUFFER_OVERRUN) — `/GS` cookie or `/guard:cf` fast-fail, specific
  to the CFG/EH members.
