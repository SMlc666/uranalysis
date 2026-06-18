use crate::model::Instruction;

pub fn format_instruction(instruction: &Instruction) -> String {
    let operands = instruction.operand_text();
    if operands.is_empty() {
        instruction.mnemonic.clone()
    } else {
        format!("{} {operands}", instruction.mnemonic)
    }
}
