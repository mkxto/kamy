# Phase 2 Contract — SSA Engine + MBA Transform Proof

Self-contained build spec. Every type, API, algorithm, file target, and
acceptance criterion needed to implement Phase 2 against the frozen Phase 1
codebase. Agents receive relevant sections; this doc is the single source of
truth for the effort.

**Scope:** lift → SSA → optimize → regalloc → codegen → link, proven by (1) a
full-SSA no-transform round-trip and (2) an MBA-transformed binary that runs
identically. The existing relocation round-trip (`kamy-link::protect`) stays for
functions not routed through SSA.

**Decisions locked:**
- φ-node SSA per grilling D7.
- Flags are I8 SSA values (0/1), not a separate Flag type — composed via
  existing And/Or/Xor/Not. Dead flag defs removed by DCE (D21).
- Full D6 semantic lift from day 1; NativeInline for unmodeled ops only.
- Win32metadata deferred; `CallingConvLookup` trait wired with Win64-default
  stub + `todo!()` for real lookup + config opt-in.
- Memory: loads/stores are ordered (no promotion/reordering in v1). No memory
  token threading yet; stores have `dest: None`, loads produce values.
- MBA as the one-transform proof (D13 config shape, initial rule set for
  add/sub/xor over all bitwidths).

---

## 1. SSA IR Types — `kamy-core/src/ir/`

New module `ir` in kamy-core. All types `pub`. Re-export from `kamy-core::ir::*`.

### 1.1 Scalars

```rust
// ir/types.rs

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ValueId(pub u32);

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct BlockId(pub u32);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IrType { I8, I16, I32, I64, I128 }

impl IrType {
    pub fn bits(self) -> u32 {
        match self { I8=>8, I16=>16, I32=>32, I64=>64, I128=>128 }
    }
}
```

### 1.2 Physical registers

```rust
// ir/phys.rs

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Gpr { Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi,
               R8, R9, R10, R11, R12, R13, R14, R15 }

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum XmmReg { Xmm0, Xmm1, Xmm2, Xmm3, Xmm4, Xmm5, Xmm6, Xmm7,
                  Xmm8, Xmm9, Xmm10, Xmm11, Xmm12, Xmm13, Xmm14, Xmm15 }

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum X86Flag { Cf, Pf, Af, Zf, Sf, Of }

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum PhysReg { Gpr(Gpr), Xmm(XmmReg), Flag(X86Flag) }
```

Derive `Ord` on `Gpr`, `XmmReg`, `X86Flag` for use in sorted sets.

Provide `Gpr::index(self) -> usize` (0–15), `XmmReg::index(self) -> usize`
(0–15), `X86Flag::ALL: [X86Flag; 6]`.

### 1.3 Operations

```rust
// ir/op.rs

/// The original bytes + register constraints of a non-modeled instruction.
#[derive(Clone, Debug)]
pub struct NativeInst {
    pub bytes: Vec<u8>,
    pub reads: Vec<PhysReg>,
    pub writes: Vec<PhysReg>,
}

#[derive(Clone, Debug)]
pub enum IrOp {
    // --- constants ---
    Const(u64),
    Undef,

    // --- data flow ---
    Copy,
    Zext, Sext, Trunc,

    // --- integer arithmetic ---
    Add, Sub, Neg,
    Mul,                    // low-half multiply (2-operand IMUL / result of MUL)
    UMulHi, SMulHi,         // high-half of widening multiply
    UDiv, SDiv,              // quotient
    URem, SRem,              // remainder

    // --- bitwise ---
    And, Or, Xor, Not,
    Shl, Shr, Sar,          // logical left, logical right, arithmetic right
    Rol, Ror,

    // --- misc integer ---
    Bswap,
    Bsf, Bsr,               // bit scan forward / reverse
    Popcnt, Lzcnt, Tzcnt,

    // --- flag extraction (arg: the result value) ---
    IsZero,                  // ZF: result == 0 → I8
    IsNeg,                   // SF: sign bit set → I8 (width-aware via arg type)
    Parity,                  // PF: even parity of low byte → I8

    // --- flag computation (args: the original operands, not the result) ---
    CarryAdd,                // CF for add
    OverflowAdd,             // OF for signed add
    BorrowSub,               // CF for sub (borrow)
    OverflowSub,             // OF for signed sub
    AuxCarryAdd,             // AF for add
    AuxBorrowSub,            // AF for sub
    CarryShl,                // CF: last bit shifted out (left)
    CarryShr,                // CF: last bit shifted out (right, logical)
    CarrySar,                // CF: last bit shifted out (right, arithmetic)

    // --- conditional ---
    Select,                  // (cond I8, true_val, false_val) → val
    SetIf,                   // (cond I8) → I8 (0 or 1, any width via Zext)

    // --- memory ---
    Load,                    // (addr I64) → val
    Store,                   // (addr I64, val) → nothing (dest: None)

    // --- SSE data movement ---
    Mov128,                  // 128-bit opaque move (MOVAPS/MOVUPS)

    // --- native passthrough ---
    NativeInline(NativeInst),

    // --- call ---
    Call { target: u64 },    // direct call; args/clobbers modeled explicitly in IR
}
```

### 1.4 Instructions and blocks

```rust
// ir/inst.rs

#[derive(Clone, Debug)]
pub struct Inst {
    pub dest: Option<ValueId>,
    pub op: IrOp,
    pub args: Vec<ValueId>,
    pub ty: IrType,           // type of produced value (I8 for flags, I64 for GPR, etc.)
}

#[derive(Clone, Debug)]
pub struct Phi {
    pub dest: ValueId,
    pub ty: IrType,
    pub args: Vec<(BlockId, ValueId)>,
}

#[derive(Clone, Debug)]
pub enum IrTerminator {
    Ret,
    Jump(BlockId),
    Branch { cond: ValueId, taken: BlockId, not_taken: BlockId },
    Unreachable,
}

#[derive(Clone, Debug)]
pub struct IrBlock {
    pub id: BlockId,
    pub phis: Vec<Phi>,
    pub insts: Vec<Inst>,
    pub term: IrTerminator,
}

#[derive(Clone, Debug)]
pub struct IrFunction {
    pub entry: BlockId,
    pub blocks: Vec<IrBlock>,
    pub next_value: u32,
}

impl IrFunction {
    pub fn alloc_value(&mut self) -> ValueId {
        let id = ValueId(self.next_value);
        self.next_value += 1;
        id
    }
    pub fn block(&self, id: BlockId) -> &IrBlock { &self.blocks[id.0 as usize] }
    pub fn block_mut(&mut self, id: BlockId) -> &mut IrBlock { &mut self.blocks[id.0 as usize] }
}
```

### 1.5 Calling convention interface

```rust
// ir/cc.rs

#[derive(Clone, Debug)]
pub struct FnSignature {
    pub args: Vec<PhysReg>,       // argument locations (GPR/XMM in order)
    pub ret: Option<PhysReg>,     // return value location
    pub clobbers: Vec<PhysReg>,   // volatile registers destroyed by the call
    pub noreturn: bool,
}

pub trait CallingConvLookup {
    fn lookup(&self, target_va: u64) -> Option<FnSignature>;
}

/// Win64 ABI default: RCX/RDX/R8/R9 (+ XMM0-3 for float), return in RAX
/// (XMM0 for float). Volatile: RAX RCX RDX R8-R11 XMM0-5.
pub struct Win64Default;
impl CallingConvLookup for Win64Default { /* return default Win64 sig */ }

/// Placeholder for the Win32metadata-backed lookup (D14).
/// Config opt-in; becomes opt-out once the .winmd preprocessor is built.
pub struct WinmdLookup;
impl CallingConvLookup for WinmdLookup {
    fn lookup(&self, _target_va: u64) -> Option<FnSignature> {
        todo!("Win32metadata .winmd preprocessor (D14)")
    }
}
```

### 1.6 File map

| File | Content |
|------|---------|
| `kamy-core/src/ir/mod.rs` | `pub mod types, phys, op, inst, cc;` + glob re-export |
| `kamy-core/src/ir/types.rs` | `ValueId`, `BlockId`, `IrType` |
| `kamy-core/src/ir/phys.rs` | `Gpr`, `XmmReg`, `X86Flag`, `PhysReg` |
| `kamy-core/src/ir/op.rs` | `NativeInst`, `IrOp` |
| `kamy-core/src/ir/inst.rs` | `Inst`, `Phi`, `IrTerminator`, `IrBlock`, `IrFunction` |
| `kamy-core/src/ir/cc.rs` | `FnSignature`, `CallingConvLookup`, `Win64Default`, `WinmdLookup` |
| `kamy-core/src/lib.rs` | Add `pub mod ir;` |

**Acceptance:** `cargo build -p kamy-core` clean, `cargo clippy -p kamy-core -- -D warnings` clean.

---

## 2. Semantic Lifter — `kamy-lift/src/`

### 2.1 Architecture

```
kamy-lift/src/
  lib.rs        — pub fn lift_function, re-exports
  state.rs      — LiftState: register→ValueId tracking, flag→ValueId tracking
  builder.rs    — IrBuilder: allocates values, appends Inst/Phi, sets terminators
  flags.rs      — emit_arith_flags, emit_logic_flags, emit_shift_flags helpers
  cond.rs       — decode_condition: ConditionCode → ValueId (I8 boolean)
  arith.rs      — lift handlers for arithmetic/bitwise/data-movement instructions
  control.rs    — lift handlers for control-flow/conditional/misc/SSE instructions
  native.rs     — NativeInline fallback: iced-x86 InstructionInfoFactory → NativeInst
```

Dependencies: `kamy-core`, `kamy-disasm`, `kamy-analysis` (for `DomTree`), `iced-x86`.

### 2.2 LiftState

Tracks the current SSA value for each physical location within a block:

```rust
pub struct LiftState {
    gprs: [ValueId; 16],           // indexed by Gpr::index()
    xmms: [ValueId; 16],           // indexed by XmmReg::index()
    flags: [ValueId; 6],           // indexed by X86Flag position in ALL
}
```

Methods: `get_gpr(Gpr) -> ValueId`, `set_gpr(Gpr, ValueId)`, same for xmm/flag.
Width tracking: GPR values are I64 (full 64-bit); sub-register writes (e.g.
`mov eax, ...`) zero-extend and update the I64 value via Trunc+Zext in the IR.

### 2.3 IrBuilder

Wraps `IrFunction` mutation during lifting:

```rust
pub struct IrBuilder<'a> {
    func: &'a mut IrFunction,
    current_block: BlockId,
}
```

Methods:
- `emit(&mut self, op: IrOp, args: &[ValueId], ty: IrType) -> ValueId`
- `emit_void(&mut self, op: IrOp, args: &[ValueId])` (for Store)
- `set_terminator(&mut self, term: IrTerminator)`
- `new_block(&mut self) -> BlockId`
- `switch_to(&mut self, block: BlockId)`

### 2.4 Lifting pattern

Per basic block (ordered by CFG, entry block first):

1. Initialize `LiftState` for the block:
   - Entry block: `LiftState` entries are initial `Undef` values (SSA construction
     replaces these later with φ or predecessor values).
   - Other blocks: same — Undef placeholders; SSA construction patches.
2. Decode instructions via `iced_x86::Decoder` (reuse `kamy_disasm` helpers).
3. For each instruction, dispatch by `Mnemonic`:
   - Modeled (D6 set): call the appropriate handler in `arith.rs` / `control.rs`.
   - Unmodeled: call `native.rs` NativeInline fallback.
4. At block end: set `IrTerminator` based on the last instruction's flow.

### 2.5 Flag emission

Three helper functions, called after each flag-affecting instruction:

```rust
/// Emit CF/OF/ZF/SF/PF/AF for an ADD-family instruction.
/// `result` is the Add's ValueId; `a` and `b` are the operands.
pub fn emit_arith_flags(b: &mut IrBuilder, s: &mut LiftState, result: ValueId, a: ValueId, b_val: ValueId, is_sub: bool);

/// Emit CF=0, OF=0, ZF, SF, PF (AF undefined) for AND/OR/XOR/TEST.
pub fn emit_logic_flags(b: &mut IrBuilder, s: &mut LiftState, result: ValueId);

/// Emit CF for SHL/SHR/SAR.
pub fn emit_shift_flags(b: &mut IrBuilder, s: &mut LiftState, result: ValueId, original_val: ValueId, count: ValueId, shift_kind: IrOp);
```

Each function calls `builder.emit(IsZero, [result], I8)` → `state.set_flag(Zf, v)`, etc.

### 2.6 Condition decoding

Shared by Jcc, CMOVcc, SETcc. Maps an iced-x86 `ConditionCode` to a `ValueId`
(I8, nonzero = true) by reading current flag values from `LiftState` and
composing via And/Or/Xor/Not:

| Condition | Expression |
|-----------|-----------|
| E / NE | ZF / Not(ZF) |
| B / AE | CF / Not(CF) |
| BE / A | Or(CF,ZF) / Not(Or(CF,ZF)) |
| S / NS | SF / Not(SF) |
| O / NO | OF / Not(OF) |
| L / GE | Xor(SF,OF) / Not(Xor(SF,OF)) |
| LE / G | Or(ZF,Xor(SF,OF)) / Not(Or(ZF,Xor(SF,OF))) |
| P / NP | PF / Not(PF) |

### 2.7 Instruction handler reference

**arith.rs** — each handler reads args from `LiftState`, emits IR ops via
`IrBuilder`, updates `LiftState` with new dest values + flags:

| x86 | IR ops | Flags |
|-----|--------|-------|
| `ADD r, r/m/i` | `Add(a,b)` | arith_flags(res,a,b,sub=false) |
| `SUB r, r/m/i` | `Sub(a,b)` | arith_flags(res,a,b,sub=true) |
| `CMP r, r/m/i` | `Sub(a,b)` (discard result) | arith_flags |
| `INC r` | `Add(a, Const(1))` | arith_flags but CF unchanged |
| `DEC r` | `Sub(a, Const(1))` | arith_flags but CF unchanged |
| `NEG r` | `Sub(Const(0), a)` | arith_flags(sub=true) + CF=IsZero(IsZero(a)) inverted |
| `AND/OR/XOR r, r/m/i` | `And/Or/Xor(a,b)` | logic_flags |
| `TEST r, r/m/i` | `And(a,b)` (discard) | logic_flags |
| `NOT r` | `Not(a)` | no flags |
| `SHL/SHR/SAR r, cl/i` | `Shl/Shr/Sar(a,count)` | shift_flags |
| `ROL/ROR r, cl/i` | `Rol/Ror(a,count)` | CF from rotation, OF for count=1 |
| `MUL r/m` | `Mul(rax,b)` + `UMulHi(rax,b)` → RAX,RDX | CF=OF=IsZero(IsZero(hi)) |
| `IMUL r/m` (1-op) | `Mul(rax,b)` + `SMulHi(rax,b)` → RAX,RDX | similar |
| `IMUL r,r/m` (2-op) | `Mul(a,b)` → dest | CF=OF from truncation check |
| `IMUL r,r/m,i` (3-op) | `Mul(a,Const(i))` → dest | same |
| `DIV r/m` | `UDiv(rdx,rax,b)` → RAX; `URem(rdx,rax,b)` → RDX | flags undefined |
| `IDIV r/m` | `SDiv(rdx,rax,b)` → RAX; `SRem(rdx,rax,b)` → RDX | flags undefined |
| `MOV r, r/m/i` | `Copy(src)` or `Const(imm)` | no flags |
| `LEA r, [mem]` | `Add(base, Add(Shl(index,Const(scale)),Const(disp)))` | no flags |
| `MOVZX r, r/m` | `Zext(src)` | no flags |
| `MOVSX/MOVSXD r, r/m` | `Sext(src)` | no flags |
| `CDQ` | `Sext(eax)` → Trunc hi 32 → EDX | no flags |
| `CQO` | `Sext(rax)` → shift right 63 → RDX (all sign bits) | no flags |
| `CDQE` | `Sext(eax to rax)` | no flags |
| `XCHG r, r` | swap via Copy | no flags |
| `BSWAP r` | `Bswap(a)` | no flags |
| `BSF/BSR r, r/m` | `Bsf/Bsr(src)` | ZF if src==0 |
| `POPCNT/LZCNT/TZCNT r, r/m` | direct op | POPCNT: ZF; LZCNT/TZCNT: CF=IsZero(src) ZF |

**control.rs:**

| x86 | IR |
|-----|-----|
| `PUSH r/m/i` | `Sub(RSP, Const(8))` → RSP; `Store(RSP, val)` |
| `POP r` | `Load(RSP)` → dest; `Add(RSP, Const(8))` → RSP |
| `CALL rel32` | push return addr (Sub+Store RSP); emit `Call{target}`; clobber volatile regs per ABI; define RAX as return |
| `RET` | `Load(RSP)` → addr; `Add(RSP, Const(8))` → RSP; `IrTerminator::Ret` |
| `JMP rel` | `IrTerminator::Jump(target_block)` |
| `Jcc rel` | `decode_condition(cc)` → cond; `IrTerminator::Branch{cond, taken, not_taken}` |
| `CMOVcc r, r/m` | `decode_condition(cc)` → cond; `Select(cond, src, dest_cur)` |
| `SETcc r/m` | `decode_condition(cc)` → cond; `SetIf(cond)` (I8) |
| `NOP/INT3` | no IR (skip) |
| `MOVAPS/MOVUPS r, r/m` | `Mov128` (I128) |
| `MOVSD/MOVSS r, r/m` | `Load`/`Copy` at I64/I32 width into XMM low |
| `XORPS r, r` | if same-reg: `Const(0)` I128; else `Xor` I128 |

### 2.8 NativeInline fallback

For any `Mnemonic` not in the D6 set: use `iced_x86::InstructionInfoFactory` to
query `info.used_registers()` → partition into reads and writes → build
`NativeInst { bytes: original_bytes, reads, writes }`. Map iced Register to
`PhysReg` (GPR sub-registers → parent Gpr). Emit `NativeInline(native)`. Update
`LiftState`: for each written PhysReg, define a new Undef value (opaque output).

### 2.9 Public API

```rust
pub fn lift_function(
    module: &Module,
    func: &Function,
    cc: &dyn CallingConvLookup,
) -> IrFunction;
```

Requires `kamy_disasm::function_instructions` for decoded instructions and
`kamy_analysis::dominator_tree` (used later by SSA construction, not by the raw
lifter — the lifter produces non-SSA IR; SSA construction runs afterward).

**Acceptance:** lift `fib` and `mix` from the round-trip test target; structurally
assert: every block has a terminator, every dest ValueId is unique across the
function, flag-producing instructions emit I8-typed results.

---

## 3. SSA Construction — `kamy-lift/src/ssa.rs`

Cytron et al. (1991) φ-insertion + renaming, using the dominator tree and
dominance frontiers from `kamy-analysis`.

### 3.1 Algorithm

1. **Identify variables:** each `(PhysReg)` that is written in ≥1 block is a
   "variable" for SSA purposes. Collect the set of blocks that define each
   variable.
2. **Insert φ-nodes:** for each variable, for each block in the dominance
   frontier of its definition blocks (iterated until stable), insert a
   `Phi { dest: fresh, ty, args: [(pred, placeholder)] }` at the start of that
   block.
3. **Rename:** DFS walk of the dominator tree. Maintain a stack per variable
   (most-recent ValueId). At each block:
   - Fill φ-node `dest` from `alloc_value`.
   - Walk instructions, replacing reads of a variable with `stack.top()` and
     recording defs by pushing the new ValueId.
   - For each successor, fill the successor's φ args for the current
     predecessor with `stack.top()` per variable.
   - On backtrack: pop defs from stacks.
4. **Clean up:** remove the Undef placeholders from the initial lift; they've
   been replaced by φ args or predecessor values.

### 3.2 Public API

```rust
pub fn construct_ssa(func: &mut IrFunction, dom: &DomTree, df: &[Vec<usize>]);
```

Modifies `func` in place: inserts φ-nodes, replaces placeholder reads.

**Acceptance:** after SSA construction on a lifted function:
- Every `ValueId` is defined exactly once (one `Inst.dest` or one `Phi.dest`).
- Every φ-node has exactly as many args as its block has predecessors.
- No remaining `Undef` in instruction args (all resolved).

---

## 4. Optimizer — `kamy-transforms/src/`

### 4.1 Pass interface

```rust
pub trait Pass {
    fn run(&self, func: &mut IrFunction) -> bool;  // true if changed
}

pub fn optimize(func: &mut IrFunction) {
    let passes: &[&dyn Pass] = &[&ConstProp, &InstCombine, &Dce, &PrunePhis];
    loop {
        let mut changed = false;
        for pass in passes { changed |= pass.run(func); }
        if !changed { break; }
    }
}
```

### 4.2 Passes

| Pass | File | Algorithm |
|------|------|-----------|
| `ConstProp` | `constprop.rs` | For each inst: if all args are `Const` → fold to `Const`. Propagate through Copy/Zext/Sext/Trunc/Add/Sub/And/Or/Xor/Not/Shl/Shr/Neg. |
| `InstCombine` | `instcombine.rs` | Pattern-match identities: `Add(x,0)→x`, `Sub(x,0)→x`, `Mul(x,1)→x`, `And(x,x)→x`, `Or(x,x)→x`, `Xor(x,x)→Const(0)`, `Sub(x,x)→Const(0)`, `Shl(x,0)→x`, `Not(Not(x))→x`, `Add(x,Neg(y))→Sub(x,y)`, `Zext(Trunc(x))` when no-op. **Must NOT reduce MBA patterns** (MBA uses runtime variables, not identity args). |
| `Dce` | `dce.rs` | Mark-sweep from roots (Store, Call, Ret-used values, NativeInline side effects). Dead = any Inst/Phi not reachable from roots. Remove. |
| `PrunePhis` | `prune_phis.rs` | Phi with all args identical (or all args == dest) → replace uses with that value. |

**Acceptance:** lift `fib`, optimize, assert: dead flag defs from lifting are
removed; `Const(0)` folded through `Add(x, Const(0))` → `x`.

---

## 5. Register Allocator — `kamy-codegen/src/regalloc.rs`

Linear-scan (Poletto & Sarkar 1999) on SSA with lifetime holes.

### 5.1 Input

`IrFunction` (post-optimizer). Each `ValueId` has a definition point (block,
instruction index) and use points. Compute live intervals.

### 5.2 Algorithm

1. Compute live intervals: for each value, `[def_point, last_use_point]`.
   Represent points as a linear index (block RPO order × instruction index).
2. Sort intervals by start point.
3. Walk intervals; for each, expire intervals that ended before this start, free
   their registers. Allocate a physical register:
   - **NativeInline constraint:** if the value is produced by a NativeInline and
     the write is to a specific `PhysReg`, pin it to that register. If the value
     is consumed by a NativeInline read at a specific `PhysReg`, ensure the
     allocator places it there (insert copy if needed).
   - **Free register selection:** prefer the register the value originally lived
     in (heuristic, reduces copies). Otherwise pick any free volatile register.
   - **Spill = reject:** if no free register → the function cannot be allocated
     without spills → return `Err(RejectionReason::RegisterPressure)`.

### 5.3 Output

```rust
pub struct RegAllocation {
    pub assignments: HashMap<ValueId, PhysReg>,
    pub copies: Vec<RegCopy>,  // inserted move instructions (before/after specific points)
}

pub struct RegCopy {
    pub point: usize,          // linear program point (before this instruction)
    pub from: PhysReg,
    pub to: PhysReg,
    pub ty: IrType,
}
```

### 5.4 Callee-saved registers

Read the function's original UNWIND_INFO to know which non-volatile registers
the prologue saves. Those registers are available for allocation. Unsaved
non-volatile registers must not be used (would corrupt the caller).

### 5.5 Public API

```rust
pub fn allocate_registers(
    func: &IrFunction,
    saved_regs: &[PhysReg],
) -> Result<RegAllocation, RejectionReason>;
```

**Acceptance:** allocate `fib` (recursive, uses RCX arg + RAX return + a few
scratch). Assert: every value assigned; no two overlapping live intervals share
a register; no spills.

---

## 6. Instruction Selection — `kamy-codegen/src/isel.rs`

### 6.1 Input

`IrFunction` + `RegAllocation`.

### 6.2 Algorithm

Walk blocks in RPO. For each `Inst`:

- **Const:** `mov reg, imm64` (or `xor reg,reg` for 0).
- **Add/Sub/And/Or/Xor/Not/Neg/Shl/Shr/Sar:** direct x86 equivalent using
  assigned registers. Width from `IrType`.
- **Mul/UMulHi/UDiv/URem etc:** multi-register x86 patterns (MUL uses RAX+RDX
  implicitly — insert copies to/from fixed regs per RegAllocation).
- **Load/Store:** `mov reg, [addr_reg]` / `mov [addr_reg], val_reg`.
- **NativeInline:** re-emit `native.bytes` verbatim. RegAllocation ensures
  operand registers are correct.
- **Copy/Zext/Sext/Trunc:** `mov` or `movzx`/`movsx` as needed.
- **Select:** `cmov` (but we need the condition in flags — re-evaluate the
  condition flag? Or: emit `test cond_reg, cond_reg` + `cmovnz`).
- **Call:** `call target` (direct). RegAllocation placed args in ABI registers.
- **Phi:** resolved by RegAllocation copies (parallel copies at predecessor ends).
- **Flag ops (IsZero, CarryAdd etc.):** these produced I8 values consumed by
  Branch/Select. At isel time, if the flag value feeds directly into a
  Branch/Select, **fuse:** emit the flag-affecting arithmetic + conditional jump
  as a single x86 pattern (e.g., `sub a,b; jnz target`). If the flag value is
  used elsewhere (stored, phi'd), materialize it: `setz al` / `setc al` etc.

### 6.3 Output

A list of `iced_x86::Instruction` per block, in order.

### 6.4 Public API

```rust
pub fn select_instructions(
    func: &IrFunction,
    alloc: &RegAllocation,
    image_base: u64,
    entry_va: u64,
) -> Vec<iced_x86::Instruction>;
```

These instructions carry the target VA so `kamy_codegen::relocate` can re-encode
them at the final `.kamy` section address.

**Acceptance:** select `fib` → decode the output → assert: contains `call`
(recursive), `cmp`, conditional branch, `add`, `ret`.

---

## 7. SSA Codegen + Wire into Linker

### 7.1 Integration point

`kamy-link/src/lib.rs` gains a new code path: for functions selected by a
profile with transforms, call `lift_function` → `construct_ssa` → `optimize` →
`allocate_registers` → `select_instructions` → `relocate` (existing) to get the
final bytes. The thunk/scrub/pdata logic is unchanged.

For functions with **no transforms but routed through SSA** (the full-SSA no-transform
round-trip), the same chain runs but with an empty transform list — the
optimizer should reduce the lifted IR back to near-original code, and regalloc
should reproduce the original register assignment (or an equivalent one).

### 7.2 Fallback

If any step fails (lift error, register pressure, codegen error), the function
falls back to the existing relocation path (`function_instructions` →
`relocate`). Report the rejection reason.

### 7.3 Acceptance — full-SSA no-transform round-trip

`kamy protect target.exe --no-transform -o protected.exe` routes functions
through the SSA chain (lift→SSA→opt→regalloc→codegen) instead of raw relocation.
The protected binary produces the same stdout and exit code.

---

## 8. MBA Transform Proof — `kamy-transforms/src/mba.rs`

### 8.1 Rule set

Each rule: `(op, arity, width_mask, replacement_fn)`.

Initial rules (manually verified correct for all inputs):

| Original | Replacement | Identity |
|----------|------------|----------|
| `Add(x,y)` | `Sub(Xor(x,y), Sub(And(Not(x),y), And(x,Not(y))))` → simpler: `Add(Xor(x,y), Shl(And(x,y), 1))` | `x+y = (x^y) + 2*(x&y)` |
| `Sub(x,y)` | `Add(Xor(x,Not(y)), Const(1))` → `Not(Sub(Not(x), y))` | `x-y = ~(~x - y)` (use Not+Sub+Not, avoiding Add which would recurse) |
| `Xor(x,y)` | `Or(And(x,Not(y)), And(Not(x),y))` | `x^y = (x&~y)\|(~x&y)` |

Rules gated by `SemanticPass.semantics` (which ops to apply) and `bitwidths`
(which widths). `probability` = chance each eligible instruction is replaced.
`iterations` = how many times the pass runs.

### 8.2 Pass

```rust
pub struct MbaPass {
    pub config: SemanticPass,
    pub rng: ChaCha8Rng,
}

impl Pass for MbaPass {
    fn run(&self, func: &mut IrFunction) -> bool { /* ... */ }
}
```

Walk each instruction. If `op` matches an enabled semantic and width matches →
roll probability → if hit, replace the instruction's subtree with the MBA
expansion (allocate new `ValueId`s, insert new instructions before the current
one, replace the original's result uses with the expansion's output).

### 8.3 Wiring

`kamy-link` checks profile `passes` list. If `MixedBooleanArithmetic` present →
after `construct_ssa`, before `optimize`, run `MbaPass::run`. The optimizer
cleans lifting artifacts but **cannot reduce MBA** (MBA operands are runtime
values, not constants/identities).

### 8.4 Acceptance

`kamy protect target.exe --profile examples/kamy.yml -o protected.exe` with a
profile containing `MixedBooleanArithmetic { iterations: 1, probability: 100 }`.
The protected binary produces the same stdout and exit code. Disassembly of a
moved function shows MBA-expanded arithmetic (visual check: single `add`
replaced by `xor`+`and`+`shl`+`add` sequence).

---

## 9. Dependency DAG + Parallelism

```
Phase A (serial, contract):  kamy-core ir module
    ↓
Phase B (2 parallel agents): kamy-lift arith.rs ‖ kamy-lift control.rs
    + inline:                 kamy-lift infrastructure (state/builder/flags/cond/native/lib)
    ↓
Phase C (serial):            kamy-lift ssa.rs (uses existing kamy-analysis dominators)
    ↓
Phase D+E (2 parallel):      kamy-transforms optimizer ‖ kamy-codegen regalloc+isel
    ↓
Phase F (serial):            wire SSA codegen into kamy-link, full-SSA round-trip
    ↓
Phase G (serial):            kamy-transforms mba.rs, wire into pipeline, MBA round-trip
```

---

## 10. Crate dependency additions

| Crate | New deps (add to Cargo.toml) |
|-------|------------|
| `kamy-lift` | `kamy-core`, `kamy-disasm`, `kamy-analysis`, `iced-x86` |
| `kamy-transforms` | `kamy-core`, `rand_chacha`, `rand_core` (already declared) |
| `kamy-codegen` | `kamy-core`, `iced-x86` (already declared) |
| `kamy-link` | `kamy-lift`, `kamy-transforms`, `kamy-analysis` (add to existing) |

---

## 11. Verification gates

After each phase:

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
```

Plus phase-specific acceptance (listed per section above).

Final gate: `tests/roundtrip/run.sh` passes (original round-trip); MBA
round-trip (new script or inline) passes.
