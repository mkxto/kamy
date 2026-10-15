# Kamy — Research Notes

Consolidated findings from primary sources, blog posts, and academic papers.
All claims are cited inline.

---

## 1. Prior Art & Reference Implementations

### 1.1 CodeDefender (Aftermath Labs) — the target product
Commercial bin2bin protector for Windows PE (x86-64 + ARM64). No source changes needed.

**Pipeline:** Analyze (PE + optional PDB → functions, CFG, unwind metadata) → Transform (composable passes: VM, mutation, MBA, CFF, constant/import hiding, diversification) → Rebuild (new protected PE + optional debug map).

**Stated coverage:** 98.9% ntoskrnl.exe functions, 95.8% chrome.dll. SEH + C++ EH exception-aware. CET + CFG mitigation-compatible. ([codedefender.io](https://codedefender.io/))

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
- Small pass set to convergence: constant promotion + folding + dead-store elimination (scoped) + inst-combine + branch folding + dead-dependency analysis.
- Register pressure avoidance as first-class allocator goal; stack-frame high-water-mark reconstruction.

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

Source: [secret.club](https://secret.club/2022/08/08/eqsat-oracle-synthesis.html), [MBA-Blast](https://www.usenix.org/system/files/sec21fall-liu-binbin.pdf)

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
