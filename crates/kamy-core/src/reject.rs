use std::fmt;

/// Reason a function was left untransformed, surfaced in the structured
/// protection report (grilling D22).
///
/// `tag` values are stable identifiers safe to assert on in CI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RejectionReason {
    /// Original function too small to host a thunk (< 5 bytes).
    NoThunkSpace,
    /// Unresolvable indirect jump: register or table-indexed dispatch that
    /// matched no known jump-table pattern.
    BadIndirectBranch,
    /// Indirect jump through a statically-known in-image pointer slot
    /// (`jmp qword [rip+disp]`). Recoverable, but the direct-ification rewrite
    /// is not yet implemented (D24 layer 0). Import/forwarder thunks are
    /// skipped, not rejected under this reason.
    ResolvableIndirect,
    /// Indirect jump recovered as a jump table (D24 layer 2). The targets are
    /// known, but moving the function needs table re-emission/retargeting, which
    /// is not yet implemented, so it stays in place.
    RecoverableSwitch,
    /// Instruction the lifter can neither model nor safely pass through verbatim.
    UnsupportedInstruction,
    /// Lifter error such as malformed code or data-in-code confusion.
    LiftFailure,
    /// SEH scope structure too complex for current support.
    SehComplex,
    /// Stack frame exceeds the configured `max_stack_copy_size`.
    StackTooLarge,
    /// Symbolization confidence fell below the acceptance threshold.
    SymbolizationUncertain,
    /// Register allocator or instruction selector failed.
    CodegenFailure,
    /// Transforms would require spills, violating the zero-spill constraint (D5).
    RegisterPressure,
}

impl RejectionReason {
    /// Stable machine-readable tag for report serialization and CI assertions.
    pub fn tag(self) -> &'static str {
        match self {
            Self::NoThunkSpace => "NoThunkSpace",
            Self::BadIndirectBranch => "BadIndirectBranch",
            Self::ResolvableIndirect => "ResolvableIndirect",
            Self::RecoverableSwitch => "RecoverableSwitch",
            Self::UnsupportedInstruction => "UnsupportedInstruction",
            Self::LiftFailure => "LiftFailure",
            Self::SehComplex => "SEHComplex",
            Self::StackTooLarge => "StackTooLarge",
            Self::SymbolizationUncertain => "SymbolizationUncertain",
            Self::CodegenFailure => "CodegenFailure",
            Self::RegisterPressure => "RegisterPressure",
        }
    }
}

impl fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tag())
    }
}
