use anyhow::{Context, bail, ensure};
use iced_x86::{Instruction, OpKind, Register};
use kamy_core::{Reference, SymbolId};

#[derive(Debug, Clone)]
pub struct InstructionReference {
    pub instruction: usize,
    pub operand: u32,
    pub reference: Reference,
}

#[derive(Debug, Clone, Default)]
pub struct SelectedInstructions {
    pub instructions: Vec<Instruction>,
    pub references: Vec<InstructionReference>,
}

pub fn bind_references(
    selected: &mut SelectedInstructions,
    image_base: u64,
    mut resolve: impl FnMut(&SymbolId) -> Option<u64>,
) -> anyhow::Result<()> {
    for fixup in &selected.references {
        let inst = selected
            .instructions
            .get_mut(fixup.instruction)
            .context("symbolic reference instruction is missing")?;
        ensure!(
            fixup.operand < inst.op_count(),
            "symbolic reference operand is missing"
        );
        let value = fixup
            .reference
            .expression
            .evaluate(|symbol| match symbol {
                SymbolId::HostImageBase => Some(image_base),
                _ => resolve(symbol),
            })
            .with_context(|| {
                format!(
                    "unresolved expression {:?} from {:?}",
                    fixup.reference.expression, fixup.reference.source
                )
            })?;
        match inst.op_kind(fixup.operand) {
            OpKind::NearBranch64 => inst.set_near_branch64(
                u64::try_from(value).context("branch target exceeds address space")?,
            ),
            OpKind::NearBranch32 => inst
                .set_near_branch32(u32::try_from(value).context("branch target exceeds 32 bits")?),
            OpKind::NearBranch16 => inst
                .set_near_branch16(u16::try_from(value).context("branch target exceeds 16 bits")?),
            OpKind::Memory if inst.is_ip_rel_memory_operand() => {
                let value = u64::try_from(value).context("RIP target exceeds address space")?;
                ensure!(
                    inst.memory_base() != Register::EIP || u32::try_from(value).is_ok(),
                    "EIP target exceeds 32 bits"
                );
                inst.set_memory_displacement64(value);
            }
            OpKind::Immediate64 => {
                let encoded = if value < 0 {
                    i64::try_from(value).context("signed symbolic operand exceeds 64 bits")? as u64
                } else {
                    u64::try_from(value).context("symbolic operand exceeds 64 bits")?
                };
                inst.set_immediate64(encoded);
            }
            OpKind::Immediate32 | OpKind::Immediate32to64 => {
                let encoded = if inst.op_kind(fixup.operand) == OpKind::Immediate32to64 {
                    i32::try_from(value)
                        .context("symbolic sign-extended operand exceeds 32 bits")?
                        as u32
                } else if value < 0 {
                    i32::try_from(value).context("signed symbolic operand exceeds 32 bits")? as u32
                } else {
                    u32::try_from(value).context("symbolic operand exceeds 32 bits")?
                };
                inst.set_immediate32(encoded);
            }
            kind => bail!("unsupported symbolic operand encoding {kind:?}"),
        }
    }
    separate_labels(selected)?;
    Ok(())
}

fn symbolic_target(
    selected: &SelectedInstructions,
    reference: &InstructionReference,
) -> Option<u64> {
    let instruction = &selected.instructions[reference.instruction];
    match instruction.op_kind(reference.operand) {
        OpKind::NearBranch64 | OpKind::NearBranch32 | OpKind::NearBranch16 => {
            Some(instruction.near_branch_target())
        }
        OpKind::Memory if instruction.is_ip_rel_memory_operand() => {
            Some(instruction.ip_rel_memory_address())
        }
        _ => None,
    }
}

// BlockEncoder uses numeric IP equality for local labels, even for an external
// operand with an explicit symbol. Relabel only local consumers on collision.
fn separate_labels(selected: &mut SelectedInstructions) -> anyhow::Result<()> {
    for index in 0..selected.instructions.len() {
        let label = selected.instructions[index].ip();
        if label == 0
            || !selected
                .references
                .iter()
                .any(|reference| symbolic_target(selected, reference) == Some(label))
        {
            continue;
        }
        let mut replacement = 1u64;
        while selected
            .instructions
            .iter()
            .any(|instruction| instruction.ip() == replacement)
            || selected
                .references
                .iter()
                .any(|reference| symbolic_target(selected, reference) == Some(replacement))
        {
            replacement = replacement
                .checked_add(1)
                .context("encoder-local labels exhausted")?;
        }
        for (index, instruction) in selected.instructions.iter_mut().enumerate() {
            if instruction.ip() == label {
                instruction.set_ip(replacement);
            }
            for operand in 0..instruction.op_count() {
                if selected
                    .references
                    .iter()
                    .any(|reference| reference.instruction == index && reference.operand == operand)
                {
                    continue;
                }
                match instruction.op_kind(operand) {
                    OpKind::NearBranch64 if instruction.near_branch_target() == label => {
                        instruction.set_near_branch64(replacement)
                    }
                    OpKind::NearBranch32 if instruction.near_branch_target() == label => {
                        instruction.set_near_branch32(u32::try_from(replacement)?)
                    }
                    OpKind::NearBranch16 if instruction.near_branch_target() == label => {
                        instruction.set_near_branch16(u16::try_from(replacement)?)
                    }
                    OpKind::Memory
                        if instruction.is_ip_rel_memory_operand()
                            && instruction.ip_rel_memory_address() == label =>
                    {
                        instruction.set_memory_displacement64(replacement)
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Code, Decoder, DecoderOptions};
    use kamy_core::{LinkField, ReferenceOrigin, Rva, SymbolicExpression};

    fn pointer(module: &str) -> Reference {
        Reference {
            source: SymbolId::Authored {
                module: module.into(),
                symbol: "caller".into(),
            },
            offset: 2,
            expression: SymbolicExpression::symbol(SymbolId::Authored {
                module: module.into(),
                symbol: "data".into(),
            }),
            field: LinkField::Absolute64,
            origin: ReferenceOrigin::Authored,
        }
    }

    #[test]
    fn exact_movabs_fixup_does_not_rebind_equal_literals_or_other_modules() {
        let literal = 0x140002000;
        let mut selected = SelectedInstructions {
            instructions: vec![
                Instruction::with2(Code::Mov_r64_imm64, Register::RAX, literal).unwrap(),
                Instruction::with2(Code::Mov_r64_imm64, Register::RCX, literal).unwrap(),
                Instruction::with2(Code::Mov_r64_imm64, Register::RDX, literal).unwrap(),
            ],
            references: vec![
                InstructionReference {
                    instruction: 0,
                    operand: 1,
                    reference: pointer("a"),
                },
                InstructionReference {
                    instruction: 2,
                    operand: 1,
                    reference: pointer("b"),
                },
            ],
        };
        bind_references(&mut selected, 0x140000000, |symbol| match symbol {
            SymbolId::Authored { module, .. } => Some(if module.as_ref() == "a" {
                0x140008008
            } else {
                0x140009010
            }),
            _ => None,
        })
        .unwrap();
        assert_eq!(selected.instructions[0].immediate64(), 0x140008008);
        assert_eq!(selected.instructions[1].immediate64(), literal);
        assert_eq!(selected.instructions[2].immediate64(), 0x140009010);
    }

    #[test]
    fn local_labels_are_independent_from_symbol_bindings() {
        let mut ret = Instruction::with(Code::Retnq);
        ret.set_ip(0x1000);
        let selected = SelectedInstructions {
            instructions: vec![
                Instruction::with_branch(Code::Jmp_rel32_64, 0x1000).unwrap(),
                ret,
            ],
            references: vec![],
        };
        let bytes = crate::relocate(&selected.instructions, 0x4000).unwrap();
        let decoded: Vec<_> = Decoder::with_ip(64, &bytes, 0x4000, DecoderOptions::NONE)
            .into_iter()
            .collect();
        assert_eq!(decoded[0].near_branch_target(), decoded[1].ip());
    }

    #[test]
    fn external_symbol_equal_to_local_label_is_never_captured() {
        let mut ret = Instruction::with(Code::Retnq);
        ret.set_ip(0x1000);
        let mut selected = SelectedInstructions {
            instructions: vec![
                Instruction::with_branch(Code::Call_rel32_64, 0).unwrap(),
                Instruction::with_branch(Code::Jmp_rel32_64, 0x1000).unwrap(),
                ret,
            ],
            references: vec![InstructionReference {
                instruction: 0,
                operand: 0,
                reference: pointer("a"),
            }],
        };
        bind_references(&mut selected, 0, |_| Some(0x1000)).unwrap();
        assert_eq!(selected.instructions[0].near_branch_target(), 0x1000);
        assert_ne!(selected.instructions[2].ip(), 0x1000);
        let bytes = crate::relocate(&selected.instructions, 0x4000).unwrap();
        let decoded: Vec<_> = Decoder::with_ip(64, &bytes, 0x4000, DecoderOptions::NONE)
            .into_iter()
            .collect();
        assert_eq!(decoded[0].near_branch_target(), 0x1000);
        assert_eq!(decoded[1].near_branch_target(), decoded[2].ip());
    }

    #[test]
    fn signed_label_difference_stays_signed_and_eip_targets_are_checked() {
        let mut reference = pointer("a");
        reference.expression = SymbolicExpression::Difference {
            left: SymbolId::Authored {
                module: "a".into(),
                symbol: "left".into(),
            },
            right: SymbolId::Authored {
                module: "a".into(),
                symbol: "right".into(),
            },
            addend: -8,
        };
        let mut selected = SelectedInstructions {
            instructions: vec![
                Instruction::with2(Code::Mov_r64_imm64, Register::RAX, 0u64).unwrap(),
            ],
            references: vec![InstructionReference {
                instruction: 0,
                operand: 1,
                reference,
            }],
        };
        bind_references(&mut selected, 0, |symbol| match symbol {
            SymbolId::Authored { symbol, .. } => Some(if symbol.as_ref() == "left" {
                0x2000
            } else {
                0x2010
            }),
            _ => None,
        })
        .unwrap();
        assert_eq!(selected.instructions[0].immediate64() as i64, -24);
        let instruction = Decoder::with_ip(
            64,
            &[0x67, 0x48, 0x8d, 0x05, 0, 0, 0, 0],
            0x1000,
            DecoderOptions::NONE,
        )
        .decode();
        selected.instructions = vec![instruction];
        selected.references[0].reference = pointer("a");
        assert!(bind_references(&mut selected, 0, |_| Some(0x1_0000_0000)).is_err());
    }
    #[test]
    fn unresolved_and_out_of_range_operands_fail() {
        let mut selected = SelectedInstructions {
            instructions: vec![
                Instruction::with2(Code::Mov_r32_imm32, Register::EAX, 0u32).unwrap(),
            ],
            references: vec![InstructionReference {
                instruction: 0,
                operand: 1,
                reference: pointer("a"),
            }],
        };
        assert!(bind_references(&mut selected, 0, |_| None).is_err());
        assert!(bind_references(&mut selected, 0, |_| Some(u64::MAX)).is_err());
        let branch = [Instruction::with_branch(Code::Jmp_rel32_64, 0x1_0000_0000).unwrap()];
        assert!(crate::relocate(&branch, 0x1000).is_err());
        assert!(crate::relocate_with_offsets(&branch, 0x1000).is_err());
        assert_ne!(
            SymbolId::Host {
                rva: Rva::new(0x1000)
            },
            SymbolId::HostImageBase
        );
    }
}
