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
    /// Recovered jump table (D24 layer 2): the dispatch matched the canonical
    /// use-def DAG template, the entry count is bound-checked, and every target
    /// lands inside the function. Case bodies are materialized as blocks during
    /// recovery and the distinct targets are this block's `successors`; `table`
    /// carries the ordered entries and addressing form so a moved function's
    /// table can be re-emitted and its dispatch retargeted (Phase B). A
    /// `jmp reg` that matches no table pattern stays `Indirect { slot: None }`.
    Switch {
        table: SwitchTable,
    },
    /// Decode failed or control left the known address space.
    Unknown,
}

/// Recovered switch-dispatch table (D24 layer 2, research.md §10.5).
///
/// Both canonical x86-64 forms collapse to this descriptor so a moved
/// function's table can be re-emitted and its dispatch retargeted (Phase B):
///
/// * LLVM table-relative — `entries` are signed `i32` deltas from `base_va`
///   (which equals the table VA); the dispatch `lea reg,[rip+table]` at
///   `dispatch_rva` is retargeted to the relocated table VA.
/// * MSVC module-base — `entries` are unsigned image-base RVAs and `base_va`
///   is the image base; the dispatch `mov r,[base+idx*4+table]` at
///   `dispatch_rva` carries the table as its displacement, retargeted to the
///   relocated table RVA.
///
/// `entries` is in table order with duplicates preserved (`len == count`), so
/// the new table is rebuilt slot-for-slot; distinct targets are surfaced as the
/// switch block's `successors`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchTable {
    /// Instruction whose memory displacement selects the table (LLVM `lea`,
    /// MSVC `mov`); the linker retargets this operand to the relocated table.
    pub dispatch_rva: Rva,
    /// Original table location in the image.
    pub table_rva: Rva,
    /// Absolute base the entries are measured from: the table VA (LLVM) or the
    /// image base (MSVC).
    pub base_va: u64,
    /// `true` = MSVC module-base RVA entries; `false` = LLVM table-relative
    /// signed `i32` deltas.
    pub base_is_image: bool,
    /// Entry count from the index bound (`cmp imm`+1 or mask `2^k`).
    pub count: u32,
    /// Case targets in table order, duplicates preserved (`len == count`).
    pub entries: Vec<Rva>,
}
