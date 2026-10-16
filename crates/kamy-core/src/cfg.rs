use crate::Rva;

/// A discovered function: its entry plus recovered basic blocks.
#[derive(Debug, Clone)]
pub struct Function {
    pub entry: Rva,
    pub blocks: Vec<BasicBlock>,
}

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub start: Rva,
    /// Exclusive end: one byte past the last instruction of the block.
    pub end: Rva,
    pub successors: Vec<Rva>,
    pub terminator: Terminator,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Terminator {
    Fallthrough(Rva),
    Jump(Rva),
    Branch {
        taken: Rva,
        not_taken: Rva,
    },
    Return,
    /// Computed branch not resolved during discovery.
    ///
    /// `slot` is `Some(rva)` for `jmp qword [rip+disp]` / `jmp qword [abs]` —
    /// the fixed pointer-slot RVA, statically known (import thunk or in-image
    /// function pointer, D24 layer 0). `None` for register or table-indexed
    /// dispatch, which carries no static slot.
    Indirect {
        slot: Option<Rva>,
    },
    /// Decode failed or control left the known address space.
    Unknown,
}
