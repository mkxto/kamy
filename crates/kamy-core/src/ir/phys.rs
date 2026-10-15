#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Gpr {
    Rax,
    Rcx,
    Rdx,
    Rbx,
    Rsp,
    Rbp,
    Rsi,
    Rdi,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
}

impl Gpr {
    pub const ALL: [Gpr; 16] = [
        Self::Rax,
        Self::Rcx,
        Self::Rdx,
        Self::Rbx,
        Self::Rsp,
        Self::Rbp,
        Self::Rsi,
        Self::Rdi,
        Self::R8,
        Self::R9,
        Self::R10,
        Self::R11,
        Self::R12,
        Self::R13,
        Self::R14,
        Self::R15,
    ];

    pub fn index(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum XmmReg {
    Xmm0,
    Xmm1,
    Xmm2,
    Xmm3,
    Xmm4,
    Xmm5,
    Xmm6,
    Xmm7,
    Xmm8,
    Xmm9,
    Xmm10,
    Xmm11,
    Xmm12,
    Xmm13,
    Xmm14,
    Xmm15,
}

impl XmmReg {
    pub const ALL: [XmmReg; 16] = [
        Self::Xmm0,
        Self::Xmm1,
        Self::Xmm2,
        Self::Xmm3,
        Self::Xmm4,
        Self::Xmm5,
        Self::Xmm6,
        Self::Xmm7,
        Self::Xmm8,
        Self::Xmm9,
        Self::Xmm10,
        Self::Xmm11,
        Self::Xmm12,
        Self::Xmm13,
        Self::Xmm14,
        Self::Xmm15,
    ];

    pub fn index(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum X86Flag {
    Cf,
    Pf,
    Af,
    Zf,
    Sf,
    Of,
}

impl X86Flag {
    pub const ALL: [X86Flag; 6] = [Self::Cf, Self::Pf, Self::Af, Self::Zf, Self::Sf, Self::Of];

    pub fn index(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum PhysReg {
    Gpr(Gpr),
    Xmm(XmmReg),
    Flag(X86Flag),
}
