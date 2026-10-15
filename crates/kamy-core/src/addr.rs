use std::fmt;

/// Relocatable virtual address: a byte offset from the module image base.
///
/// The IR never stores absolute addresses; layout is applied at emit time.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Rva(u32);

impl Rva {
    pub const ZERO: Rva = Rva(0);

    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u32 {
        self.0
    }

    pub fn checked_add(self, delta: u32) -> Option<Self> {
        self.0.checked_add(delta).map(Self)
    }
}

impl From<u32> for Rva {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<Rva> for u32 {
    fn from(rva: Rva) -> Self {
        rva.0
    }
}

impl fmt::Debug for Rva {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Rva({:#010x})", self.0)
    }
}

impl fmt::Display for Rva {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#010x}", self.0)
    }
}
