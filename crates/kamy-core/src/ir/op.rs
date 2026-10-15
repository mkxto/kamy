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

    // --- memory ---
    Load,
    Store,

    // --- SSE data movement (128-bit) ---
    Mov128,

    // --- native passthrough ---
    NativeInline(NativeInst),

    // --- call ---
    Call { target: u64 },
}
