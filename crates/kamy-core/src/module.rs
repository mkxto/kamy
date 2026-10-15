use crate::{Function, Relocation, Rva, Symbol};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Machine {
    X64,
}

/// A parsed image: the rewriting substrate for a single binary.
#[derive(Debug, Clone)]
pub struct Module {
    pub image_base: u64,
    pub machine: Machine,
    pub entry_point: Option<Rva>,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub relocations: Vec<Relocation>,
    pub functions: Vec<Function>,
}

impl Module {
    pub fn section_at(&self, rva: Rva) -> Option<&Section> {
        self.sections.iter().find(|s| s.contains(rva))
    }

    /// Bytes from `rva` to the end of its containing section's materialized data.
    pub fn bytes_at(&self, rva: Rva) -> Option<&[u8]> {
        self.section_at(rva)?.bytes_at(rva)
    }

    pub fn is_executable(&self, rva: Rva) -> bool {
        self.section_at(rva).is_some_and(|s| s.flags.execute)
    }
}

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub rva: Rva,
    pub virtual_size: u32,
    /// Section contents as laid out in memory, truncated to the bytes present
    /// in the file (shorter than `virtual_size` when the tail is zero-fill).
    pub data: Vec<u8>,
    pub flags: SectionFlags,
}

impl Section {
    pub fn contains(&self, rva: Rva) -> bool {
        let start = self.rva.get();
        let end = start.saturating_add(self.virtual_size);
        (start..end).contains(&rva.get())
    }

    pub fn bytes_at(&self, rva: Rva) -> Option<&[u8]> {
        let offset = rva.get().checked_sub(self.rva.get())? as usize;
        self.data.get(offset..)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SectionFlags {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}
