use crate::Rva;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SymbolId {
    Host {
        rva: Rva,
    },
    Authored {
        module: std::sync::Arc<str>,
        symbol: std::sync::Arc<str>,
    },
    Generated {
        name: std::sync::Arc<str>,
    },
    HostImageBase,
}

#[derive(Debug, Clone)]
pub struct Symbol {
    pub id: SymbolId,
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
