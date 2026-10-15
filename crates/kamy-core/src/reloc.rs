use crate::Rva;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Relocation {
    pub rva: Rva,
    pub kind: RelocKind,
}

/// Base-relocation kinds from the PE `.reloc` directory (`IMAGE_REL_BASED_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocKind {
    /// Padding entry; no fixup.
    Absolute,
    /// 32-bit fixup (`HIGHLOW`).
    HighLow,
    /// 64-bit fixup (`DIR64`).
    Dir64,
}
