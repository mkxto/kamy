use kamy_core::ir::{BlockId, Inst, IrBlock, IrFunction, IrOp, IrTerminator, IrType, ValueId};

pub(crate) struct IrBuilder<'a> {
    pub(crate) func: &'a mut IrFunction,
    current_block: BlockId,
}

impl<'a> IrBuilder<'a> {
    pub(crate) fn new(func: &'a mut IrFunction, block: BlockId) -> Self {
        Self {
            func,
            current_block: block,
        }
    }

    pub(crate) fn emit(&mut self, op: IrOp, args: &[ValueId], ty: IrType) -> ValueId {
        let dest = self.func.alloc_value();
        self.func.block_mut(self.current_block).insts.push(Inst {
            dest: Some(dest),
            op,
            args: args.to_vec(),
            ty,
        });
        dest
    }

    pub(crate) fn emit_void(&mut self, op: IrOp, args: &[ValueId]) {
        self.func.block_mut(self.current_block).insts.push(Inst {
            dest: None,
            op,
            args: args.to_vec(),
            ty: IrType::I64,
        });
    }

    pub(crate) fn set_terminator(&mut self, term: IrTerminator) {
        self.func.block_mut(self.current_block).term = term;
    }

    #[allow(dead_code)]
    pub(crate) fn new_block(&mut self) -> BlockId {
        let id = BlockId(self.func.blocks.len() as u32);
        self.func.blocks.push(IrBlock {
            id,
            phis: Vec::new(),
            insts: Vec::new(),
            term: IrTerminator::Unreachable,
        });
        id
    }

    pub(crate) fn switch_to(&mut self, block: BlockId) {
        self.current_block = block;
    }

    #[allow(dead_code)]
    pub(crate) fn current_block(&self) -> BlockId {
        self.current_block
    }
}
