use iced_x86::Instruction;

use crate::CodegenError;

pub fn assemble(instrs: &[Instruction], new_va: u64) -> Result<Vec<u8>, CodegenError> {
    crate::relocate(instrs, new_va)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Code, Register};

    #[test]
    fn assemble_simple() {
        let instrs = vec![
            Instruction::with2(Code::Mov_r64_imm64, Register::RAX, 42u64).unwrap(),
            Instruction::with(Code::Retnq),
        ];
        let bytes = assemble(&instrs, 0x140001000).unwrap();
        assert!(!bytes.is_empty());
    }
}
