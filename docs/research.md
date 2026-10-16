# Kamy — Research Notes

Consolidated findings from primary sources, blog posts, and academic papers.
All claims are cited inline.

---

## 1. Prior Art & Reference Implementations

### 1.1 CodeDefender (Aftermath Labs) — the target product
Commercial bin2bin protector for Windows PE (x86-64 + ARM64). No source changes needed.

**Pipeline:** Analyze (PE + optional PDB → functions, CFG, unwind metadata) → Transform (composable passes: VM, mutation, MBA, CFF, constant/import hiding, diversification) → Rebuild (new protected PE + optional debug map).

**Stated coverage** (internal production-scale targets): hvix64.exe 98.9%, chrome.dll 95.8%, ntoskrnl.exe 92.0% functions transformed. SEH + C++ EH exception-aware. CET + CFG mitigation-compatible, ACG-aware profiles. ARM64 shipped; Android listed as upcoming. Formats: EXE, DLL, drivers, incl. UEFI modules where supported. ([codedefender.io](https://codedefender.io/))

**Key product differentiators:**
- Per-function, per-layer composable protection profiles (not one opaque preset)
- Functions that can't be safely transformed are *reported*, not silently broken
- Debug map generation for crash investigation in protected builds
- API + CLI + SDK for CI pipeline integration

### 1.2 BLARE2 (Aftermath Labs internal engine)
Custom disassembler → SSA IR → optimization pipeline → compiler backend (instruction selector, register allocator, assembler) → linker. AMD64 + ARM64. Used for both obfuscation and devirtualization — same engine, both directions.

**Critical design insights (from devirt blog posts):**
- Backend lowers optimized IR to near-1:1 reinsertable native code — "that last part separates it from most lifting frameworks." They explicitly reject LLVM for this backend.
- Byte-level memory model with store-forwarding, individual flag SSA values, backward-walkable def-use DAG.
- Declarative pattern-rewrite DSL over IR DAGs, run to fixed point.
- Small pass set to convergence: constant promotion + folding + dead-store elimination (scoped) + inst-combine + branch folding + dead-dependency analysis. Passes are not independent — "each pass feeds the next, and the VM scaffolding unravels as a consequence of all of them running together."
- Register pressure avoidance as first-class allocator goal. Rationale, verbatim: "If the register allocator spills, the devirtualized code gets its own stack frame alongside the original function's stack frame... stack-passed arguments to calls inside the devirtualized region will be misread by IDA, Binary Ninja, and anything else an analyst loads the binary into." The backend may select different instructions/registers than the original, but never spills.
- Dead-dependency analysis: registers/flags clobbered by the native code immediately after the exit point are dead and their symbolic expressions are dropped. Their ZF example: the IR carries the full expression tree for a symbolic ZF even though the very next native instruction overwrites it.
- Concrete-RSP lifting: RSP starts concrete (everything else symbolic) so stack-pointer arithmetic constant-folds and the generic load/store machinery handles stack accesses with no special casing. Limitation they accept: functions with dynamic stack allocations (alloca/VLA) are unsupported.
- Stack-frame high-water-mark reconstruction: the concretized RSP at sink points (calls, boxed instructions) reveals the original frame size, and the prolog/epilog is rebuilt from it. If spilling ever happens, the original frame is placed after the recompiler's own spill frame.

Sources: [Themida devirt](https://aftermathlabs.net/blog/09/05/2026/), [Tencent VM devirt](https://aftermathlabs.net/blog/31/07/2026/)

### 1.3 PERSES — minimal reliable bin2bin mutation engine
X86 instruction-level mutation engine for PE files. Replaces each targeted instruction with a semantically compatible larger sequence.

**Only mutates:** `PUSH`, `MOV`, `CALL`, `JMP`, `ADD`, `XOR` + jump tables. Small subset = reliability.

**Transforms:**
| Original | Mutation |
|----------|----------|
| `CALL target` | `push return_addr; jmp target` — breaks decompiler CFG |
| `MOV reg, imm32+` | Two-stage: encrypt hi/lo halves, decrypt, OR together |
| `ADD x, y` | `~(~x - y)` or `(x - ~y) - 1` |
| `XOR x, y` | `(x & ~y) \| (~x & y)` |
| All | Operand encryption + runtime decrypt stubs |

**Correctness machinery:**
- EFLAGS preservation: PUSHF/POPF around every mutation that taints flags
- Scratch registers: push/pop around every temporary use
- Relocatable operand detection via Zydis instruction segments → convert to RVA before encryption, add base at runtime
- Branch fixups: label system to retarget JCC/JMP/CALL after code growth
- Jump table recovery: entry count from bounds-check immediate + 1
- Bail-out: refuse to mutate unsupported operand sizes / addressing modes

**Field results:** 17,057 functions in CS:GO `engine.dll` mutated in ~2 min. Binary 6.2→25.8 MB (~4×). IDA function detection 22K→8K. Broke Aimware signature scanning.

Source: [PERSES](https://aftermathlabs.net/blog/13/04/2022/), [GitHub](https://github.com/mike1k/perses)

### 1.4 Theodosius — linker-level framework (plumbing blueprint)
Operates on COFF/lib files. Replaces the linker. Controls symbol placement and linking.

**Key architecture concepts we adopt:**
- **Ordered, type-filtered pass pipeline:** passes inherit a base class, declare which symbol types they run on, are registered explicitly in caller-defined order.
- **Relocation rebasing:** relocations inside routines are rebased to be symbol-relative (or instruction-relative when decomposed to `.split`). This makes code position-independent of original placement — the enabler for free relayout.
- **Recursive used-symbol walk:** transitive reachability from entry point via relocations, with memoization. Dead-symbol elimination.
- **Per-instruction decomposition** (`.split` sections): one symbol per instruction for maximum placement freedom.

**Explicit limitations (= our reliability requirements):** No SEH, no CET, no jump tables, no TLS. x86-64 only. MSVC COFF only.

Source: [Theodosius](https://aftermathlabs.net/blog/06/05/2022/), [Docs](https://docs.back.engineering/theo/)

### 1.5 VTIL / NoVmp (can1357 / blog.can.ac) — IR design blueprint
Translation-oriented optimizing IL built for binary de/re-writing. The single most transferable design asset.

**Key design rules:**
- **Keep the native ISA concrete.** Unmodeled instructions pass through as inline native bytes. Stack and physical registers remain explicit. Round-trip guarantee: can always re-emit correct code even for ops you don't optimize.
- **SSA emulated cheaply** by tagging operands with the source virtual instruction pointer (VIP). No full φ-construction; values built by backward-tracing a basic block.
- **Symbolic expressions as a tree, copy-on-write.** O(1) constructor-time hashing. Thread-local simplifier caches (no global lock) for thread-safe parallel processing.
- **Relocations/casts as first-class opaque IR leaves.** Never constant-fold a relocation. Width changes are explicit `_ucast`/`_cast` nodes.
- **Known/unknown bit-vector abstract domain** (known_bits, unknown_bits, bit_count) with closed-form transfer functions for NOT/OR/AND/XOR/SHL/ROT. Sound but incomplete — safe for dead-bit elimination.
- **Cost-gated directive rewriter:** φ(e) punishes depth exponentially. Universal rules always applied; join rules applied speculatively and kept only if cost drops. Infinite-loop prevention via cache pre-insertion before recursion.

Source: [blog.can.ac](https://blog.can.ac/2020/04/11/writing-an-optimizing-il-compiler-for-dummies-by-a-dummy/), [VTIL-Core](https://github.com/vtil-project/VTIL-Core), [NoVmp](https://github.com/can1357/NoVmp)

### 1.6 k0mkc (ゴロリ) — Rust bin2bin framework
Japanese developer building a bin2bin recompilation framework 100% in Rust. Closest existing implementation to our goal.

**Demonstrated capabilities:**
- Multithreaded analysis: ~250MB il2cpp binary → 755,580 begin addresses, 755,579 functions, 6,999,939 basic blocks parsed in **5.19s**
- SEH scope recompilation: supports functions with `__C_specific_handler` SEH scopes (non C++ EH), C_SCOPE_TABLE entries, UNWIND_INFO/.pdata/.xdata rebuilding
- MSVC compiler test compatibility: 58 SEH test cases, all passing
- Devirtualization of Tencent VM, Zakynthos VM (PUBG anti-cheat), Denuvo anti-cheat
- Uses **iced-x86** for disassembly/encoding in Rust
- YAML-based per-function configuration for transforms
- Guided symbolic evaluation: lift → IR → concrete evaluator → optimize → codegen
- **Call-site metadata from Win32metadata**: pre-defined arg types/counts/noreturn for 350 DLLs (~20K functions) to enable precise CALL lifting, stored as perfect hash tables for O(1) lookup

**Technical observations:**
- CALL lifting is the most fragile part of binary lifting — conservative assumptions (preserve all regs) trade optimality for correctness. Win32metadata provides trusted narrowing.
- iced-x86 gotcha: `VMLAUNCH`/`VMRESUME`/`VMCALL`/`SYSCALL` have FlowControl=Call but branch target is always 0 — needs a wrapper returning `Option<u64>`
- Loop handling: detect backedges via concretized VPC instead of fully unrolling — O(1) per loop vs O(n²)
- Denuvo anti-cheat uses LLVM-based bin2bin (NOPs match LLVM MC NOP table, not MSVC); opaque predicates are all statically resolvable; MBA is simple enough to fold via IR inst-combine rules

Sources: [k0mkc blog](https://k0mkc.hatenablog.com/), posts from July-September 2026

---

## 2. Techniques Catalog

### 2.1 Mutation / Instruction Substitution
Replace individual instructions with semantically-equivalent larger sequences. Encrypt operands at build time, inject runtime decrypt stubs.

**Correctness requirements:** preserve EFLAGS (PUSHF/POPF), preserve scratch registers (push/pop), detect and handle relocatable operands (convert to RVA), repair all RIP-relative operands and intra-routine branches after size changes. Bail out on unsupported addressing.

### 2.2 Mixed Boolean Arithmetic (MBA)
Rewrite simple expressions as complex tangles mixing arithmetic and bitwise ops. E.g. `x + y → (x^y) + 2*(x&y)`, `x ^ y → (x & ~y) | (~x & y)`.

**Tencent VM's published MBA identity ruleset** (claimed exhaustive; applied recursively to build expressions). The same list doubles as the attacker's reduction playbook: an inst-combine carrying these rules, run to fixed point, fully collapses the generated linear MBA.

```
(A|B) + (A&B)        = A + B
(A^B) + (A&B)        = A | B
(A|B) - (A&B)        = A ^ B
((A|B)^A) + A        = A | B
~((~A ^ ~B) | ~A)    = A & B
~(((A^B) & ~B) ^ ~A) = A & B
A - (A - (A&B))      = A & B
B - (((A&B)&B) ^ B)  = A & B
((c&A) ^ A) | A      = A              [+ all operand orderings]
(A & ((A^c) | c))    = A
(((A&c) ^ A) | A)    = A
(((c|A) ^ c) | A)    = A
(((A^B)|B) & A) + B  = A + B
(A&B) + (A|B)        = A + B
~(A - c)             = -A + (c-1)
~( <A+c gadget> )    = -A + c
```

The inverse pairs `(A^B)+(A&B) = A|B` and `(A|B)-(A&B) = A^B` bracket the same linear family our initial add/sub rules occupy — reducible by this ruleset and by known tooling. Acceptable for the v1 round-trip proof; MBA strength (nonlinear/polynomial, machine-generated) is D12+ work.

**MBA on branch targets** (Themida post): encoding an indirect-branch destination as an MBA expression over opaque values prevented concretization — "this worked well for a while" — but is now trivially reducible; CodeDefender claims stronger, unpublished techniques in its heavier tiers. Corollary for future CFF/opaque-predicate work: branch-adjacent MBA must not be statically resolvable.

**EFLAGS layout cross-check** (from the Tencent VJCC rewrite templates): CF = 0x1 (idx 0), PF = 0x4 (idx 1), AF = 0x10 (idx 2, never read by Jcc), ZF = 0x40 (idx 3), SF = 0x80 (idx 4), OF = 0x800 (idx 5).

**Design against known attacks:**
| Attack | What it beats | Design defense |
|--------|--------------|----------------|
| MBA-Blast / SiMBA | All linear MBA | Use nonlinear/polynomial MBA |
| Arybo | Small-width per-bit ANF | Use 64-bit, polynomial, cross-word MBA |
| SSPAM | Catalogued pattern rules | Machine-generate identities, randomize structure |
| GAMBA | Some nonlinear MBA | Interleave with opaque data deps + runtime key material |
| QSynth/Xyntia | Small-arity expressions | High-arity, stateful, memory-touching regions |
| Equality saturation (egg) | Phase-ordering-bound term rewriting | Per-instance diversification, scattered terms, point-function predicates |

**Strongest posture:** polynomial/nonlinear MBA + scattered terms + point-function-like behavior + materialized opaque constants whose small-bit-width I/O is unrepresentative.

Source: [secret.club](https://secret.club/2022/08/08/eqsat-oracle-synthesis.html), [MBA-Blast](https://www.usenix.org/system/files/sec21fall-liu-binbin.pdf), [Tencent VM devirt](https://aftermathlabs.net/blog/31/07/2026/), [Themida devirt](https://aftermathlabs.net/blog/09/05/2026/)

### 2.3 Control-Flow Flattening (CFF)
Dismantle structured control flow into `while(swVar){ switch(swVar){…} }` dispatcher. Must preserve exception regions, SEH/C++ EH unwind descriptors, and live-register state. Combine with opaque predicates / MBA on the switch variable to resist constant-propagation.

### 2.4 Opaque Predicates
Inject predicates whose truth value is known to the obfuscator but hard for analysts/SMT to resolve. Must be provably invariant on all reachable states. Dynamic OPs vary per-execution to defeat static solvers.

**Weakness:** Denuvo anti-cheat's opaque predicates are all statically resolvable via IR — "they do nothing" (k0mkc). Design predicates grounded in true number-theoretic invariants or pointer aliasing, not simple flag arithmetic.

### 2.5 Constant & Reference Hiding
Encrypt constants, obscure memory references, protect imports. Two-stage split loads (encrypt hi/lo separately, OR together). Import obfuscation via FNV hashing or encrypted IAT.

### 2.6 Binary Diversification
Instruction reordering, basic-block shuffling, register reassignment. Lightweight, breaks signature matching. Per-build variance (SigBreaker).

### 2.7 Operand Encryption + Decrypt Stubs
Build-time encryption of immediates/displacements/memory operands. Runtime decrypt instructions injected into the stream. Must handle relocatable operands specially (RVA conversion).

---

## 3. Windows x64 SEH/Unwind — The Hard Reliability Frontier

### 3.1 Data Structures
- `.pdata` section: array of `RUNTIME_FUNCTION` entries `{BeginAddress, EndAddress, UnwindInfoAddress}` — sorted, covering every non-leaf function
- `.xdata` / `UNWIND_INFO`: version, flags (`UNW_FLAG_EHANDLER`/`UHANDLER`/`CHAININFO`), prolog size, frame register, unwind codes (`UWOP_PUSH_NONVOL`, `UWOP_ALLOC_SMALL/LARGE`, `UWOP_SET_FPREG`, `UWOP_SAVE_NONVOL`, `UWOP_PUSH_MACHFRAME`)
- `C_SCOPE_TABLE`: for `__C_specific_handler`, array of `{BeginAddress, EndAddress, HandlerAddress, JumpTarget}` scopes describing `__try`/`__except`/`__finally` regions

### 3.2 How VMs Handle SEH (Tencent VM pattern — the model to copy)
1. Cover entire VM range with one large `.pdata` entry + custom language-specific handler
2. Create a **phantom/dummy function** (never executed) whose `UNWIND_INFO` describes saves of all 9 non-volatile registers — parked at `[RBP+0]` for the VM's lifetime
3. VM entry uses `UWOP_SET_FPREG` with RBP as frame register (RBP saved at entry, never scratched)
4. On exception: VM handler copies guest non-volatile regs into the phantom function's save area, writes guest RIP into slot 8 below guest RSP, returns `ExceptionContinueSearch`
5. Unwinder follows `[RBP+0]` to the phantom function, applies its unwind codes → guest regs restored to CONTEXT
6. Unwinder reads the staged RIP/RSP → correct guest state restored

Zakynthos VM variant uses `UWOP_PUSH_MACHFRAME` (normally used by interrupt handlers) to restore RSP/RIP to guest state directly.

### 3.3 Requirements for Our Tool
- Parse/rebuild RUNTIME_FUNCTION, UNWIND_INFO, C_SCOPE_TABLE for every rewritten function
- Handle chained unwind info for boxed/native escape instructions
- Re-point scope table entries (BeginAddress, EndAddress, HandlerAddress, JumpTarget) to new locations after code transformation
- Validate with MSVC compiler SEH test suite (58+ tests)
- Make try/except/finally work without user macros (the explicit bar against Code Virtualizer)

---

## 4. CET Shadow Stack Compatibility

Any control-flow faking that abuses RET/CALL must actively reconcile the shadow stack.

**Pattern (from Tencent VM):**
1. Feature check: zero a register, execute `RDSSPQ reg` (encoded in hint-NOP space → retires as NOP without CET, leaving dest untouched), test if register changed
2. If CET active: `INCSSPQ 2` to discard orphaned shadow return addresses from faked CALL/RET sequences

VMProtect is NOT CET-compatible — its VMEXIT uses RET as a CALL substitute. Design requirement: never break the shadow stack invariant.

---

## 5. Symbolization — The Reliability Bottleneck

### 5.1 The Core Problem
"Is `0x42424242` a pointer that must move, or a constant that must stay?" Getting one wrong silently corrupts the binary. KAIST's "Reassembly is Hard" (USENIX'23) proves no existing tool (Ramblr, RetroWrite, Ddisasm) is error-free.

### 5.2 Design Strategy (metadata-first, inference-second)
1. **Consume ground truth first:** PE relocations (`.reloc` section), symbol tables, `.pdata`/`.xdata` unwind info, debug info (PDB). These are guaranteed-correct references.
2. **Infer the residual:** jump-table entries (often lack relocations even in PIE), computed pointers, address-of-label patterns. Use weighted-evidence voting (Ddisasm model): register def-use chains, register value analysis, data-access-pattern analysis.
3. **Graceful degradation:** below a confidence threshold per function, fall back to an address-translation table (correct-but-slow, Multiverse model) instead of fast-but-broken rewriting. Per-function policy.

### 5.3 Data Model
Adopt GTIRB/Egalito's **Link/SymbolicExpression** overlay on bytes. Every reference becomes a first-class symbolic object so layout changes are correct-by-construction. Never store absolute addresses in the IR.

Classify each candidate with the KAIST Type I-VII scheme (atomic/composite × absolute/PC-rel/GOT-rel/label-rel). Composites (`label±const`, `label1-label2`) are 97.4% of cases — not edge cases.

---

## 6. Verification & Testing Strategy

### 6.1 Layered Pipeline (cheapest first)
1. **Differential reassembly self-test:** rewrite with no transform, require byte/label equivalence. Catches symbolization bugs. Wire into CI.
2. **Per-instruction lifter validation:** SMT-prove decode→IR semantics per opcode offline (PLDI'20 method found 29 bugs in McSema). Do once per ISA.
3. **Per-transform equivalence gate (STOKE two-tier):** fast test-vector run with Hamming partial credit → sound SMT bit-vector proof on mutated block before commit.
4. **Loop/function-level equivalence** (DDEC) for transforms that change control structure (CFF).
5. **Dynamic smoke:** run the target's own test suite on the rewritten binary.

### 6.2 MBA Rule Verification
Every MBA rewrite rule verified once at authoring time with SMT bit-vector proof. Rules expressed as structured data (VTIL directive model) for machine-verification.

### 6.3 Coverage Tracking
Measure fraction of targeted functions successfully transformed. CodeDefender reports 92-99% depending on binary. Track per-module, report untransformable functions with reasons.

### 6.4 External verification corpus (Aftermath Labs)

**bintests** ([aftermathlabs/bintests](https://github.com/aftermathlabs/bintests)) — ~3k prebuilt 32/64-bit PE files for verifying bin2bin transformations, used by their CI. Usage model matches ours: run the original, capture stdout, transform, compare. The `seh/` folder is 64-bit PEs that print nothing on success — verify via exit code 0. Contents: zasm examples, OpenSSL test bins, LLVM JIT examples (Fibonacci, IRTransforms, OrcV2), testfloat, coremark, Microsoft `windows_seh_tests` + `compiler-tests` (the concrete SEH suite §3.3 calls for), corkami weird PEs, vulnerable drivers, VisualUEFI, UE5 demo, loki real-world crypto, plus deliberate disassembler-breakers (recursion, mutually-calling functions, noreturn, all sorts of jump tables). Compile options deliberately mixed (/O2, /GL, /LTCG not uniform).

**LTCG hazard** (their warning, verbatim): "code compiled with /GL you cannot assume volatile registers are really volatile. The compiler can do some non-abi stuff with functions inside of the binary." Implication: modeling calls with the Win64-default clobber set is conservative-safe when we rewrite the *caller*; the unsound direction is rewriting a *callee* whose /GL callers relied on non-ABI preservation — our regalloc would use volatile scratch they expected to survive. Must be settled (profile/target-selection rules) before transforming functions in real LTCG binaries.

**binstats** ([aftermathlabs/binstats](https://github.com/aftermathlabs/binstats)) — their coverage methodology, no debug info used: per-binary `func-info.csv` (function/BB counts, reference counts), `inst-data.csv`, coverage pie per binary, and leaf-status classification per MSVC stack-usage types — a stealable function-selection heuristic. Shipped targets: chrome.dll, hvix64, ntoskrnl, ntdll, mpengine, nvlddmkm, bootmgfw.efi, Telegram, Signal, Discord, xul, CS2 engine2, notepad++.

**Supporting assets:** llvm-msvc (LLVM with MSVC 2022 compatibility — toolchain for MSVC-ABI-faithful test binaries), testfloat-pe (TestFloat as import-free PEs — clean FP round-trip targets), coremark-pe (perf-measurable round-trip target), themida-devirt (original/virtualized/devirtualized triplet), pdbgen2 + elderscroll (PDB rewriting from old PDB + address mapping — prior art for a debug-map feature), pelite fork (their PE parsing stack).

---

## 7. Rust Ecosystem

| Crate | Role |
|-------|------|
| `iced-x86` | x86/x64 disassembler, assembler, encoder, decoder. Used by k0mkc. |
| `object` | Parse PE/ELF/Mach-O. Read/write sections, symbols, relocations. |
| `goblin` | Alternative PE/ELF/Mach-O parser. |
| `pdb` | Parse PDB debug info. |
| `egg` | E-graph equality saturation library. Used by secret.club for MBA. |
| `z3` (bindings) | SMT solver for verification. |
| `rayon` | Data parallelism for per-function processing. |
| `cranelift` | Potential codegen backend (alternative to custom). |
| `serde` / `toml` / `serde_yaml` | Configuration/profile serialization. |

---

## 8. What Makes Protectors Fail (Anti-Patterns to Avoid)

From the devirt posts, these are documented concretization footholds:

1. **Indirect targets that concretize** — the entire devirt attack hinges on concretizing control flow
2. **Simple/recursive MBA on branch targets** — "now trivially reducible" via inst-combine at fixed point
3. **VM state in a known memory range** — enables scoped constant promotion + dead-store elimination
4. **Single-load VIP** — attackers auto-recover and build loop backedges
5. **Fixed RSP-displacement VMEXIT** — pattern-matchable, trivially classifiable
6. **Matchable VJCC DAGs** — fixed flag-computation shapes → pre-defined rewrite rules strip them
7. **Opaque predicates from simple flag arithmetic** — all statically resolvable (Denuvo anti-cheat example)
8. **Single-thread VM spinlock** (Code Virtualizer) — "completely nullifies multithreading"
9. **Requiring user macros for switch/try-except** (Code Virtualizer) — "poor engineering"

---

## 9. Key References

### Blogs & Projects
- CodeDefender: https://codedefender.io/
- Aftermath Labs blog: https://aftermathlabs.net/blog/
- PERSES: https://github.com/mike1k/perses
- Theodosius: https://git.back.engineering/_xeroxz/Theodosius/
- VTIL-Core: https://github.com/vtil-project/VTIL-Core
- NoVmp: https://github.com/can1357/NoVmp
- blog.can.ac (VTIL internals): https://blog.can.ac/2020/04/11/writing-an-optimizing-il-compiler-for-dummies-by-a-dummy/
- secret.club (MBA/eqsat): https://secret.club/2022/08/08/eqsat-oracle-synthesis.html
- k0mkc blog: https://k0mkc.hatenablog.com/
- Win32metadata: https://github.com/microsoft/win32metadata
- Aftermath Labs bintests (bin2bin PE corpus): https://github.com/aftermathlabs/bintests
- Aftermath Labs binstats (coverage stats): https://github.com/aftermathlabs/binstats
- Aftermath Labs themida-devirt (devirt triplet): https://github.com/aftermathlabs/themida-devirt
- Aftermath Labs llvm-msvc (MSVC-compatible LLVM): https://github.com/aftermathlabs/llvm-msvc

### Academic Papers
- Ddisasm/Datalog Disassembly (USENIX'20): arXiv:1906.03969
- GTIRB: arXiv:1907.02859
- RetroWrite (Oakland'20): https://hexhive.epfl.ch/publications/files/20Oakland.pdf
- Egalito (ASPLOS'20): https://github.com/columbia/egalito
- Reassembly is Hard (USENIX'23): https://github.com/SoftSec-KAIST/Reassessor
- McSema/remill: https://github.com/lifting-bits/mcsema
- rev.ng: https://github.com/revng/revng
- MBA-Blast (USENIX'21): https://www.usenix.org/system/files/sec21-liu-binbin.pdf
- SiMBA: arXiv:2209.06335
- GAMBA: arXiv:2305.06763
- STOKE (ASPLOS'13): arXiv:1211.0557
- Alive2 (PLDI'21): https://github.com/AliveToolkit/alive2
- Binary Lifter Validation (PLDI'20): found 29 bugs in McSema
- SBR Survey (CSUR'19): https://dl.acm.org/doi/abs/10.1145/3316415

## 10. Jump-Table Empirical Study (2026-10-16)

Classification of every `Terminator::Indirect` block in our two reference binaries
(tooling: throwaway iced decoder over discovered CFGs; numbers are measured, not
estimated). Motivation: `BadIndirectBranch` is the #1 rejection reason — 52% of
rejects on target.exe, 67% on kernel32 — and D24's layering had never been
validated against real binaries.

### 10.1 kernel32.dll — the "rejection problem" is mostly forwarder accounting

925 indirect blocks across 922 functions:

| Class | Count | Nature | D24 disposition |
|-------|-------|--------|-----------------|
| Export forwarder stubs | 843 blocks | 6–7-byte functions, `jmp qword [rel IAT]`; kernel32 has a literal `fothk` section, targets land in the `.rdata` IAT window (RVA 0x89000–0x8C000) | **Not protection targets.** Classify-and-skip; never count as rejection |
| Internal static-pointer jumps | 67 blocks | Same `jmp qword [rel X]` shape inside real functions (tail-calls through data pointers) | Resolve pointer statically; rewrite 6-byte indirect jmp as 5-byte `jmp rel32` (fits in place, 1 byte pad) |
| RVA-relative switch tables | 11 blocks / 12 funcs | Canonical MSVC shape (below) | Layer 2 pattern match; recover + retarget |
| Bare `jmp reg` dispatch | 4 blocks | Computed control flow, no static table | Genuinely dynamic → stay rejected (correct D22 behavior) |

Per-function: 910 of 922 are static-jump-only; only 12 functions contain real
register-dispatch. Conclusion: on this binary "jump-table recovery" is 99%
**classification**, not table decoding.

### 10.2 target.exe (Rust/LLVM) — real tables dominate, plus a discovery bug

148 indirect blocks across 114 functions (no exports; all internal):

| Class | Count | Nature | D24 disposition |
|-------|-------|--------|-----------------|
| Static-pointer jumps | 59 blocks | `jmp qword [rel X]`, X in `.rdata` (vtable slots / GOT-like dispatch) | Same as kernel32: static resolve + direct-ify |
| RVA-relative switch tables | 51 blocks | `movsxd rX,[base+idx*4]; add rX,base; jmp rX`, plus an `and`-masked no-bounds-check variant (`and r8d,3`) | Layer 2 (+ layer 3 for masked forms) |
| Dynamic tail dispatch | 38 blocks | `mov r9,[rcx+0x18]; mov rcx,rax; jmp r9` vtable tail-calls, register thunks | Genuinely dynamic → reject |

**Discovery artifact (fixed):** recovery followed far branch targets across
`.pdata` boundaries, producing functions with multi-hundred-KiB spans (kernel32
max 478 KiB) that swallowed real neighbors — inflating function and rejection
counts and falsely tripping `SEHComplex`. Fix: bound each function's recovery at
the next `.pdata`/export/entry start (these partition x64 code into
non-overlapping ranges) and treat `jmp` to a known start as a tail call. Spans
collapsed (kernel32 478 KiB → 17.7 KiB, target 84 KiB → 2.9 KiB) and `moved`
rose (kernel32 1214 → 1271, target 169 → 197). A residual handful of phantom
call-seeds still land inside real code; removing them needs noreturn tracking
(post-noreturn bytes currently truncate to a conservative `LiftFailure`).

### 10.3 The canonical recoverable shape (both compilers)

```asm
; MSVC (kernel32)                      ; Rust/LLVM (target.exe)
lea rdx,[rel IMG+off]                  lea r15,[rel IMG+off]   ; or mov r15,base
mov ecx,[rdx+rax*4+TABLE]              and r8d,3               ; optional mask
add rcx,rdx                           movsxd r8,[r15+r8*4]
jmp rcx                               add r8,r15
                                       jmp r8
```

Entries are 4-byte RVA offsets (not absolute pointers) — confirmed: **no
.reloc entries cover them** (kernel32: 528 relocs, none in the table ranges).
D24 layer 1 (relocations as ground truth) is therefore mostly empty in
practice; the operative layers are pattern matching (count from bounds-check
immediate +1, cross-check every entry lands inside the function's .pdata
bounds) and register-value analysis for masked forms.

### 10.4 Re-weighted D24 implementation order

1. **Layer 0 — classify static `jmp [rel X]`** (biggest win, near-zero risk) —
   **DONE.** Discovery now tags `jmp qword [rip+disp]` with its fixed pointer
   slot (`Terminator::Indirect { slot: Option<Rva> }`, computed in
   `kamy-disasm`). The linker (`kamy-link::classify`) tests the slot against the
   import IAT (`PeFile::import_slots`): IAT hit → import/forwarder thunk, skip
   (not a protection target, never a rejection); other in-image slot →
   `ResolvableIndirect` (recoverable, direct-ification pending); register or
   table-indexed (`slot: None`) → stays `BadIndirectBranch`.
   Measured (after the runaway-recovery fix in §10.2 re-ran discovery): kernel32
   `BadIndirectBranch` 922 → **9** + `ResolvableIndirect`; target.exe 114 → **30**
   (`jmp [__imp_…]` import thunks skipped — exact IAT-slot membership is finer
   than this section's coarse ".rdata window" bucket, which over-counted
   target.exe static-pointers). `moved` set correct on both.
2. **Fix runaway recovery / phantom seeds in discovery** — **DONE** (dominant
   mechanism). Recovery is bounded at the next `.pdata`/export/entry start (see
   §10.2); the 478 KiB phantom spans are gone and `moved` rose. Residual phantom
   call-seeds inside real code need noreturn tracking (follow-up).
3. **Layer 2 — canonical switch pattern** with entry-count + .pdata
   bounds cross-check, reject on ambiguity (D24 unchanged).
4. **Layer 3 — masked-table register analysis** (narrow; only real user is
   the `and`-mask variant).

Dynamic vtable tail-calls remain honest rejections — protecting them is
runtime-tier (Phase 7) territory, not static recovery.

### 10.5 Cross-validation — BLARE2 (CodeDefender) technique report

Source: "Technical Challenges of Indirect Control Flow",
https://codedefender.io/blog/2024/07/02 (Jul 2, 2024; their rewriting engine
B.L.A.R.E., in Rust). Their documented variants map 1:1 onto the shapes measured
in §10.1–10.3:

| BLARE2 variant | Our measurement |
|---------------|------------------|
| LLVM 64-bit, table-relative int32 deltas (`lea tbl; movsxd; add; jmp reg`) | target.exe 51 blocks (Rust/LLVM) |
| MSVC 64-bit, module-base RVAs (`lea base; mov ecx,[base+idx*4+off]; add; jmp`) | kernel32 11 blocks |
| MSVC multi-level: byte index table + adjacent RVA target table (sparse switches) | **not yet observed in our binaries — catalog anyway** |
| 32-bit: absolute entries, fully reloc-backed | out of scope (x64 only); confirms layer 1 is a 32-bit-only mechanism |
| `call/jmp [mem]` resolving into the **IAT range** = import, never a switch | kernel32 843 forwarders + 67 internal IAT jumps — formalizes our "layer 0" |

Their mechanism (validated in production: Chrome >97%, Unreal 99%, Windows
components >95% rewrite coverage — *with* reject-on-ambiguity, i.e. even BLARE2
does not claim 100% on system binaries):

- **Matching engine: use-def DAG + VF2 subgraph isomorphism** (`petgraph`
  `subgraph_isomorphisms_iter`), not text patterns. Node comparison collapses
  mov/sign-extended-mov variants, ignores constants and RIP-relative operands,
  and ignores register identity (allocator variance). New variants are macro-added.
- **Entry count from the bound**: `cmp imm; ja default` immediate + 1; `CMP`
  normalized as `SUB` in the DAG so only "a bound exists" matters.
- **Unbounded tables → reject.** Adjacent tables are common, so guess-and-check
  ("catastrophic results after obfuscation"); Rust unbounded `match` tables are
  their dominant unrecoverable class. Our `and r8d,3` masked form is *implicitly
  bounded* (count = 2^k) and stays recoverable.
- **noreturn tracking upstream**: mis-advancing past noreturn calls makes the
  disassembler decode table data as code — a plausible contributor to our
  phantom-seed artifact (§10.2). They gate noreturn on "all terminators are
  interrupts/known-noreturn calls" after a retpoline false positive.
- **Documented gap**: the post covers detection/parsing only — **no re-emit or
  retarget algorithm** for a moved table. That design burden is ours: after a
  function moves, its table must be copied/re-encoded (deltas or RVAs
  recomputed for the new layout) and the dispatch re-emitted to match.
- **Test corpus**: jump-table-specific corpus at
  `github.com/backengineering/bintests/tree/master/misc/jtables` (distinct from
  the aftermathlabs corpus adopted in D25) — adopt as the D24 conformance set.

Layer 2's implementation choice is therefore settled by prior art: a small
use-def DAG per variant + `petgraph` VF2 (passes dependency gates C1/C2),
with the cmp-derived (or mask-derived) bound as the entry count and .pdata
cross-checks (§10.4) as our own additional ground truth.
