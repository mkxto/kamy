use std::fmt;

/// Reason a function was left untransformed, surfaced in the structured
/// protection report (grilling D22).
///
/// `tag` values are stable identifiers safe to assert on in CI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RejectionReason {
    /// Unresolvable indirect jump: register or table-indexed dispatch that
    /// matched no known jump-table pattern.
    BadIndirectBranch,
    /// Indirect jump through a statically-known in-image pointer slot
    /// (`jmp qword [rip+disp]`). Recoverable, but the direct-ification rewrite
    /// is not yet implemented (D24 layer 0). Import/forwarder thunks are
    /// skipped, not rejected under this reason.
    ResolvableIndirect,
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
    /// Logical RSP depends on an unprovable runtime value.
    FrameDynamic,
    /// Reachable stack states disagree or violate the call/return contract.
    FrameConflict,
    /// Frame arithmetic or an address displacement is not representable.
    FrameOverflow,
    /// The concrete frame exceeds the 16 MiB implementation bound.
    FrameResourceLimit,
    /// A flag dependency cannot be represented by the supported IR semantics.
    UnsupportedFlags,
    /// Excluded from SSA lowering by an explicit [`crate::FunctionSelector`].
    /// Its body remains resident; verified reference operands may be rebased.
    /// This is not an engine limitation.
    Deselected,

    // --- Target reject taxonomy (CodeDefender parity). Documented for a precise
    // breakdown; producers for several of these are not wired yet.
    /// Body falls through into the next function (no clean boundary).
    FallthroughToFunction,
    /// Far (inter-segment) jump.
    FarJump,
    /// Call target could not be validated/relocated.
    InvalidCall,
    /// Unconditional jump target could not be validated/relocated.
    InvalidJump,
    /// Conditional jump target could not be validated/relocated.
    InvalidJcc,
    /// Software interrupt that cannot be relocated.
    InvalidInterrupt,
    /// A data/code reference could not be resolved to the moved layout.
    InvalidReference,
    /// Raw decode of the function bytes failed.
    DecodeFailure,
    /// TSX `xabort`/`xend` in the body.
    XAbortOrXEnd,
    /// Reachable only via an exception path we do not model.
    UnhandledException,
    /// Exception unwind-epilogue (footer) record is malformed.
    EhInvalidFooter,
    /// Function does not own the UNWIND_INFO it points at (shared/chained).
    EhFunctionDoesntOwnInfo,
    /// Could not create an exception bucket for the moved function.
    EhNoBucketCreation,
    /// UNWIND_INFO fields are inconsistent.
    EhBadInfo,
    /// Chained unwind record forms an invalid chain.
    EhInvalidChain,
    /// A reference inside the exception footer failed to relocate.
    EhFooterReferenceFailed,
}

impl RejectionReason {
    /// Stable machine-readable tag for report serialization and CI assertions.
    pub fn tag(self) -> &'static str {
        match self {
            Self::BadIndirectBranch => "BadIndirectBranch",
            Self::ResolvableIndirect => "ResolvableIndirect",
            Self::UnsupportedInstruction => "UnsupportedInstruction",
            Self::LiftFailure => "LiftFailure",
            Self::SehComplex => "SEHComplex",
            Self::StackTooLarge => "StackTooLarge",
            Self::SymbolizationUncertain => "SymbolizationUncertain",
            Self::CodegenFailure => "CodegenFailure",
            Self::FrameDynamic => "FrameDynamic",
            Self::FrameConflict => "FrameConflict",
            Self::FrameOverflow => "FrameOverflow",
            Self::FrameResourceLimit => "FrameResourceLimit",
            Self::UnsupportedFlags => "UnsupportedFlags",
            Self::Deselected => "Deselected",
            Self::FallthroughToFunction => "FallthroughToFunction",
            Self::FarJump => "FarJump",
            Self::InvalidCall => "InvalidCall",
            Self::InvalidJump => "InvalidJump",
            Self::InvalidJcc => "InvalidJcc",
            Self::InvalidInterrupt => "InvalidInterrupt",
            Self::InvalidReference => "InvalidReference",
            Self::DecodeFailure => "DecodeFailure",
            Self::XAbortOrXEnd => "XAbortOrXEnd",
            Self::UnhandledException => "UnhandledException",
            Self::EhInvalidFooter => "EhInvalidFooter",
            Self::EhFunctionDoesntOwnInfo => "EhFunctionDoesntOwnInfo",
            Self::EhNoBucketCreation => "EhNoBucketCreation",
            Self::EhBadInfo => "EhBadInfo",
            Self::EhInvalidChain => "EhInvalidChain",
            Self::EhFooterReferenceFailed => "EhFooterReferenceFailed",
        }
    }
}

impl fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tag())
    }
}
