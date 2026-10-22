use super::op::IrOp;
use super::types::{BlockId, IrType, ValueId};

#[derive(Clone, Debug)]
pub struct Inst {
    pub dest: Option<ValueId>,
    pub op: IrOp,
    pub args: Vec<ValueId>,
    pub ty: IrType,
}

#[derive(Clone, Debug)]
pub struct Phi {
    pub dest: ValueId,
    pub ty: IrType,
    pub args: Vec<(BlockId, ValueId)>,
}

#[derive(Clone, Debug)]
pub enum IrTerminator {
    Ret,
    NoReturn,
    Jump(BlockId),
    Branch {
        cond: ValueId,
        taken: BlockId,
        not_taken: BlockId,
    },
    Tail {
        target: crate::Reference,
    },
    Unreachable,
}

#[derive(Clone, Debug)]
pub struct IrBlock {
    pub id: BlockId,
    pub phis: Vec<Phi>,
    pub insts: Vec<Inst>,
    pub term: IrTerminator,
}

#[derive(Clone, Debug)]
pub struct IrFunction {
    pub entry: BlockId,
    pub blocks: Vec<IrBlock>,
    pub next_value: u32,
}

impl IrFunction {
    pub fn alloc_value(&mut self) -> ValueId {
        let id = ValueId(self.next_value);
        self.next_value += 1;
        id
    }

    pub fn block(&self, id: BlockId) -> &IrBlock {
        &self.blocks[id.0 as usize]
    }

    pub fn block_mut(&mut self, id: BlockId) -> &mut IrBlock {
        &mut self.blocks[id.0 as usize]
    }
}
