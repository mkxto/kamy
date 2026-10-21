use crate::Rva;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReferenceKind {
    DirectBranch,
    RipRelative,
    /// A loader-relocated, 64-bit virtual-address field.
    Absolute,
    /// A known, 32-bit image-relative address field.
    ImageRelative,
    /// A recovered CFG edge consumed by table-free switch lowering.
    Switch,
    /// A runtime-function boundary regenerated with its exception metadata.
    Unwind,
    EntryPoint,
    /// The consumer cannot be rewritten; the target must remain resident.
    Opaque,
}

/// Instruction references identify the instruction; data references identify the
/// encoded field. An entry-point reference uses source RVA zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reference {
    pub source: Rva,
    pub target: Rva,
    pub kind: ReferenceKind,
}
