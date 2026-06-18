use crate::{
    error::{EncodeError, TextError},
    model::{DecodeStatus, FlowKind, Instruction, InstructionKind},
};

const RET_WORD: u32 = 0xd65f03c0;

pub fn encode(instruction: &Instruction) -> Result<Vec<u8>, EncodeError> {
    if instruction.mnemonic == "ret"
        && instruction.operands.is_empty()
        && instruction.flow == FlowKind::Return
    {
        return Ok(RET_WORD.to_le_bytes().to_vec());
    }
    Err(EncodeError::UnsupportedForm(instruction.mnemonic.clone()))
}

pub fn parse(text: &str, address: u64) -> Result<Instruction, TextError> {
    if text.trim() == "ret" {
        return Ok(Instruction {
            address,
            size: 4,
            bytes: RET_WORD.to_le_bytes().to_vec(),
            mnemonic: "ret".to_string(),
            operands: Vec::new(),
            text: "ret".to_string(),
            kind: InstructionKind::Return,
            flow: FlowKind::Return,
            branch_target: None,
            status: DecodeStatus::Complete,
        });
    }
    Err(TextError::UnknownMnemonic(text.trim().to_string()))
}
