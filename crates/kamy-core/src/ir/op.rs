use super::phys::PhysReg;

#[derive(Clone, Debug)]
pub struct NativeInst {
    pub bytes: Vec<u8>,
    pub references: Vec<crate::OperandReference>,
    pub reads: Vec<PhysReg>,
    pub writes: Vec<PhysReg>,
}

#[derive(Clone, Debug)]
pub enum IrOp {
    // --- constants ---
    Const(u64),
    Address(crate::Reference),
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
    /// Binary low product, or unary RAX low-result projection of the high
    /// product in `args[0]`, before any instruction overwrites that result.
    Mul,
    /// Unsigned high half of a 2N-bit product. The first N-bit input occupies
    /// RAX and the result RDX; both physical registers are clobbered.
    UMulHi,
    /// Signed high product with the same physical contract as [`IrOp::UMulHi`].
    SMulHi,
    /// Divide the concatenation `[high, low]` by `divisor`, all N-bit values.
    /// Inputs high/low occupy RDX/RAX; quotient occupies RAX. Division by zero
    /// and an unrepresentable N-bit quotient fault, even if the result is dead.
    UDiv,
    /// Signed 2N-bit dividend and N-bit divisor, truncated toward zero, with
    /// the same physical and fault contract as [`IrOp::UDiv`].
    SDiv,
    /// RDX remainder projection of the matching division in `args[0]`.
    /// It MUST precede any instruction that overwrites that physical result.
    URem,
    /// RDX projection of [`IrOp::SDiv`]; nonzero remainder has dividend's sign.
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
        target: crate::Reference,
        clobbers: Vec<PhysReg>,
    },
    /// Indirect call; `args[0]` is the target address, `args[1..]` the ABI
    /// argument values. Lowered to `call reg`.
    CallIndirect {
        clobbers: Vec<PhysReg>,
    },
    CallResult {
        register: PhysReg,
    },
}
