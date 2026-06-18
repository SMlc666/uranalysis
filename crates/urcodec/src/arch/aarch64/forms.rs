use crate::{
    error::{EncodeError, TextError},
    form::{FormId, InstructionForm},
    model::{Architecture, DecodeStatus, FlowKind, Instruction, InstructionKind},
};

const RET_WORD: u32 = 0xd65f03c0;

static FORMS: &[InstructionForm] = &[InstructionForm::new(
    FormId::new(Architecture::Aarch64, "ret"),
    "ret",
    InstructionKind::Return,
    FlowKind::Return,
    encode_ret,
    parse_ret,
)];

pub fn all_forms() -> &'static [InstructionForm] {
    FORMS
}

pub fn encode(instruction: &Instruction) -> Result<Vec<u8>, EncodeError> {
    FORMS
        .iter()
        .find_map(|form| form.encode(instruction))
        .ok_or_else(|| EncodeError::UnsupportedForm(instruction.mnemonic.clone()))
}

pub fn parse(text: &str, address: u64) -> Result<Instruction, TextError> {
    FORMS
        .iter()
        .find_map(|form| form.parse(text, address))
        .ok_or_else(|| TextError::UnknownMnemonic(text.trim().to_string()))
}

fn encode_ret(instruction: &Instruction) -> Option<Vec<u8>> {
    (instruction.mnemonic == "ret"
        && instruction.operands.is_empty()
        && instruction.flow == FlowKind::Return)
        .then(|| RET_WORD.to_le_bytes().to_vec())
}

fn parse_ret(text: &str, address: u64) -> Option<Instruction> {
    (text.trim() == "ret").then(|| Instruction {
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
    })
}
