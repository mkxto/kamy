use crate::Rva;

#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub rva: Rva,
    pub kind: SymbolKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    Function,
    Export,
    Import,
    EntryPoint,
    Data,
}
