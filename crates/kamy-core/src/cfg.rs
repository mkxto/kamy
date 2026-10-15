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
    /// Computed branch not resolved during discovery (e.g. a jump table).
    Indirect,
    /// Decode failed or control left the known address space.
    Unknown,
}
