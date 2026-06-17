use crate::{
    arch::aarch64::format::render_instruction,
    model::{DecodeStatus, FlowKind, Instruction, InstructionKind, Operand},
};

pub fn decode_word(word: u32, address: u64) -> Instruction {
    unknown(word, address)
}

pub fn unknown(word: u32, address: u64) -> Instruction {
    let operands = vec![Operand::AbsoluteAddress(u64::from(word))];
    Instruction {
        address,
        size: 4,
        bytes: word.to_le_bytes().to_vec(),
        mnemonic: ".word".to_string(),
        text: render_instruction(".word", &operands),
        operands,
        kind: InstructionKind::Unknown,
        flow: FlowKind::Fallthrough,
        branch_target: None,
        status: DecodeStatus::Unknown,
    }
}
