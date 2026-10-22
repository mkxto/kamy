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
pub struct HostReference {
    pub source: Rva,
    pub target: Rva,
    pub kind: ReferenceKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SymbolicExpression {
    Symbol {
        symbol: crate::SymbolId,
        addend: i64,
    },
    Difference {
        left: crate::SymbolId,
        right: crate::SymbolId,
        addend: i64,
    },
}

impl SymbolicExpression {
    pub fn symbol(symbol: crate::SymbolId) -> Self {
        Self::Symbol { symbol, addend: 0 }
    }

    pub fn with_addend(self, offset: i64) -> Option<Self> {
        match self {
            Self::Symbol { symbol, addend } => Some(Self::Symbol {
                symbol,
                addend: addend.checked_add(offset)?,
            }),
            Self::Difference {
                left,
                right,
                addend,
            } => Some(Self::Difference {
                left,
                right,
                addend: addend.checked_add(offset)?,
            }),
        }
    }

    pub fn evaluate(
        &self,
        mut resolve: impl FnMut(&crate::SymbolId) -> Option<u64>,
    ) -> Option<i128> {
        match self {
            Self::Symbol { symbol, addend } => {
                Some(i128::from(resolve(symbol)?) + i128::from(*addend))
            }
            Self::Difference {
                left,
                right,
                addend,
            } => {
                Some(i128::from(resolve(left)?) - i128::from(resolve(right)?) + i128::from(*addend))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinkField {
    Absolute64,
    ImageRelative32,
    Relative32 { bias: u8 },
}

impl LinkField {
    pub fn width(self) -> u32 {
        match self {
            Self::Absolute64 => 8,
            Self::ImageRelative32 | Self::Relative32 { .. } => 4,
        }
    }

    pub fn encode_into(
        self,
        value: i128,
        field_va: u64,
        image_base: u64,
        output: &mut [u8],
    ) -> Option<()> {
        if output.len() != self.width() as usize {
            return None;
        }
        match self {
            Self::Absolute64 => {
                let value = if value < 0 {
                    i64::try_from(value).ok()? as u64
                } else {
                    u64::try_from(value).ok()?
                };
                output.copy_from_slice(&value.to_le_bytes());
            }
            Self::ImageRelative32 => output.copy_from_slice(
                &u32::try_from(value.checked_sub(i128::from(image_base))?)
                    .ok()?
                    .to_le_bytes(),
            ),
            Self::Relative32 { bias } => {
                let end = field_va.checked_add(4)?.checked_add(u64::from(bias))?;
                output.copy_from_slice(
                    &i32::try_from(value.checked_sub(i128::from(end))?)
                        .ok()?
                        .to_le_bytes(),
                );
            }
        }
        Some(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReferenceOrigin {
    HostAnalysis,
    HostMetadata,
    Authored,
    Generated,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Reference {
    pub source: crate::SymbolId,
    pub offset: u32,
    pub expression: SymbolicExpression,
    pub field: LinkField,
    pub origin: ReferenceOrigin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperandReference {
    pub instruction: Rva,
    pub operand: u32,
    pub reference: Reference,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SymbolId;

    #[test]
    fn source_qualified_symbols_and_signed_composites_remain_distinct() {
        let a = SymbolId::Authored {
            module: "a".into(),
            symbol: "object:1:7".into(),
        };
        let b = SymbolId::Authored {
            module: "b".into(),
            symbol: "object:1:7".into(),
        };
        assert_ne!(a, b);
        let expression = SymbolicExpression::Difference {
            left: a.clone(),
            right: b.clone(),
            addend: -8,
        };
        assert_eq!(
            expression.evaluate(|symbol| if *symbol == a {
                Some(0x2000)
            } else if *symbol == b {
                Some(0x2010)
            } else {
                None
            }),
            Some(-24)
        );
        assert!(
            SymbolicExpression::Symbol {
                symbol: a,
                addend: i64::MAX
            }
            .with_addend(1)
            .is_none()
        );
    }

    #[test]
    fn encoding_checks_signed_addends_biases_and_integer_bounds() {
        let mut word = [0u8; 4];
        LinkField::Relative32 { bias: 3 }
            .encode_into(0x1000 - 3, 0x2000, 0, &mut word)
            .unwrap();
        assert_eq!(i32::from_le_bytes(word), -0x100a);
        LinkField::ImageRelative32
            .encode_into(0x140000010, 0, 0x140000000, &mut word)
            .unwrap();
        assert_eq!(u32::from_le_bytes(word), 16);
        assert!(
            LinkField::ImageRelative32
                .encode_into(0x13fffffff, 0, 0x140000000, &mut word)
                .is_none()
        );
        assert!(
            LinkField::Relative32 { bias: 0 }
                .encode_into(0x1_0000_0000, 0, 0, &mut word)
                .is_none()
        );
        assert!(
            LinkField::Relative32 { bias: 0 }
                .encode_into(0, u64::MAX, 0, &mut word)
                .is_none()
        );
        let mut qword = [0u8; 8];
        LinkField::Absolute64
            .encode_into(-24, 0, 0, &mut qword)
            .unwrap();
        assert_eq!(i64::from_le_bytes(qword), -24);
        assert!(
            LinkField::Absolute64
                .encode_into(i128::from(u64::MAX) + 1, 0, 0, &mut qword)
                .is_none()
        );
        assert!(
            LinkField::Absolute64
                .encode_into(0, 0, 0, &mut word)
                .is_none()
        );
    }
}
