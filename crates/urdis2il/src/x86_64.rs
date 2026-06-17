use crate::{lifter::unsupported_instruction, model::IlInstruction, Result};

pub(crate) fn lift(instruction: &urdisassembly::Instruction) -> Result<IlInstruction> {
    Ok(unsupported_instruction(
        instruction,
        "x86-64 lifting rule not implemented for mnemonic",
    ))
}
