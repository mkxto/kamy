use super::phys::PhysReg;

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
    /// Absolute VA of a RIP-relative data reference; lowered to a
    /// position-independent `lea reg, [rip+disp]` whose displacement the encoder
    /// recomputes for the relocated code.
    RipAddr(u64),
    Undef,

    // --- data flow ---
    Copy,
    Zext,
    Sext,
    Trunc,

    // --- integer arithmetic ---
    Add,
    Sub,
    Neg,
    Mul,
    UMulHi,
    SMulHi,
    UDiv,
    SDiv,
    URem,
    SRem,

    // --- bitwise ---
    And,
    Or,
    Xor,
    Not,
    Shl,
    Shr,
    Sar,
    Rol,
    Ror,

    // --- misc integer ---
    Bswap,
    Bsf,
    Bsr,
    Popcnt,
    Lzcnt,
    Tzcnt,

    // --- flag extraction (arg: the result value) → I8 ---
    IsZero,
    IsNeg,
    Parity,

    // --- flag computation (args: the original operands) → I8 ---
    CarryAdd,
    OverflowAdd,
    BorrowSub,
    OverflowSub,
    AuxCarryAdd,
    AuxBorrowSub,
    CarryShl,
    CarryShr,
    CarrySar,

    // --- conditional ---
    Select,
    SetIf,
    /// Logical negation of a 0/1 flag boolean → I8 (`x == 0`). Distinct from
    /// bitwise [`IrOp::Not`]: the condition algebra (`cond.rs`) and flag
    /// inversions keep the flag-value invariant that every flag SSA value is
    /// exactly 0 or 1, which bitwise one's-complement would break (`!1 == 0xFE`
    /// stays truthy under `test;jnz`).
    BoolNot,

    // --- memory ---
    Load,
    Store,

    // --- SSE data movement (128-bit) ---
    Mov128,

    // --- native passthrough ---
    NativeInline(NativeInst),

    // --- live-out marker (DCE root, no codegen output) ---
    Use,
    // --- call ---
    Call {
        target: u64,
    },
    /// Indirect call; `args[0]` is the target address, `args[1..]` the ABI
    /// argument values. Lowered to `call reg`.
    CallIndirect,
}
