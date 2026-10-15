use iced_x86::{FlowControl, Instruction, OpKind};

/// Absolute virtual-address target of a direct near branch or call.
///
/// Returns `None` for indirect control flow and for the instructions that
/// iced reports as `FlowControl::Call` yet carry no branch operand
/// (VMLAUNCH/VMRESUME/VMCALL/SYSCALL/SYSENTER): those have a `near_branch_target`
/// of `0`, so dispatching on flow control alone would fabricate a target.
pub fn branch_target(instr: &Instruction) -> Option<u64> {
    if instr.op0_kind() != OpKind::NearBranch64 {
        return None;
    }
    match instr.flow_control() {
        FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch | FlowControl::Call => {
            Some(instr.near_branch_target())
        }
        _ => None,
    }
}
