#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ValueId(pub u32);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct BlockId(pub u32);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IrType {
    I8,
    I16,
    I32,
    I64,
    I128,
}

impl IrType {
    pub fn bits(self) -> u32 {
        match self {
            Self::I8 => 8,
            Self::I16 => 16,
            Self::I32 => 32,
            Self::I64 => 64,
            Self::I128 => 128,
        }
    }

    pub fn bytes(self) -> u32 {
        self.bits() / 8
    }
}
