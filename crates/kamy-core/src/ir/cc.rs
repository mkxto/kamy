use super::phys::{Gpr, PhysReg, XmmReg};

#[derive(Clone, Debug)]
pub struct FnSignature {
    pub args: Vec<PhysReg>,
    pub ret: Option<PhysReg>,
    pub clobbers: Vec<PhysReg>,
    pub noreturn: bool,
}

pub trait CallingConvLookup {
    fn lookup(&self, target_va: u64) -> Option<FnSignature>;
}

/// Win64 ABI default: RCX/RDX/R8/R9 integer args, XMM0-3 float args,
/// return in RAX (XMM0 for float). Volatile: RAX RCX RDX R8-R11 XMM0-5.
pub struct Win64Default;

impl Win64Default {
    fn default_signature() -> FnSignature {
        use Gpr::*;
        FnSignature {
            args: vec![
                PhysReg::Gpr(Rcx),
                PhysReg::Gpr(Rdx),
                PhysReg::Gpr(R8),
                PhysReg::Gpr(R9),
            ],
            ret: Some(PhysReg::Gpr(Rax)),
            clobbers: vec![
                PhysReg::Gpr(Rax),
                PhysReg::Gpr(Rcx),
                PhysReg::Gpr(Rdx),
                PhysReg::Gpr(R8),
                PhysReg::Gpr(R9),
                PhysReg::Gpr(R10),
                PhysReg::Gpr(R11),
                PhysReg::Xmm(XmmReg::Xmm0),
                PhysReg::Xmm(XmmReg::Xmm1),
                PhysReg::Xmm(XmmReg::Xmm2),
                PhysReg::Xmm(XmmReg::Xmm3),
                PhysReg::Xmm(XmmReg::Xmm4),
                PhysReg::Xmm(XmmReg::Xmm5),
            ],
            noreturn: false,
        }
    }
}

impl CallingConvLookup for Win64Default {
    fn lookup(&self, _target_va: u64) -> Option<FnSignature> {
        Some(Self::default_signature())
    }
}

/// Placeholder for the Win32metadata-backed lookup (grilling D14).
/// Opt-in via config; becomes opt-out once the .winmd preprocessor is built.
pub struct WinmdLookup;

impl CallingConvLookup for WinmdLookup {
    fn lookup(&self, _target_va: u64) -> Option<FnSignature> {
        todo!("Win32metadata .winmd preprocessor (D14)")
    }
}
