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

/// Recovered switch dispatch (D24 layer 2, research.md §10.5), lowered to a
/// tableless compare ladder (no table survives in the output, matching
/// CodeDefender — see docs/code_defender.md §"Switch / jump-table handling").
///
/// The lifter reads `index_reg` at dispatch and emits `index == k → entries[k]`
/// as ordinary conditional branches to the case blocks; the final value falls
/// through to `entries[last]` (the preceding bound check guarantees the index is
/// in range). `entries[i]` is the case target for index value `i`, in table
/// order with duplicates preserved; distinct targets are the switch block's
/// `successors`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchTable {
    /// Register holding the zero-based switch index at dispatch.
    pub index_reg: crate::ir::Gpr,
    /// RVA of the table-load instruction (`mov r,[base+index*4+table]`); the
    /// lifter stops there and replaces the dispatch tail with the ladder.
    pub dispatch_rva: Rva,
    /// Case target per index value (`entries[i]` = target for index `i`).
    pub entries: Vec<Rva>,
}
