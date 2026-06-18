use crate::{
    error::{EncodeError, TextError},
    form::{FormId, InstructionForm},
    model::{Architecture, DecodeStatus, FlowKind, Instruction, InstructionKind, Operand},
};

const RET_WORD: u32 = 0xd65f03c0;

static FORMS: &[InstructionForm] = &[
    InstructionForm::new(
        FormId::new(Architecture::Aarch64, "ret"),
        "ret",
        InstructionKind::Return,
        FlowKind::Return,
        encode_ret,
        parse_ret,
    ),
    InstructionForm::new(
        FormId::new(Architecture::Aarch64, "b_imm26"),
        "b",
        InstructionKind::Branch,
        FlowKind::Branch,
        encode_b_imm26,
        parse_b_imm26,
    ),
];

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

fn encode_b_imm26(instruction: &Instruction) -> Option<Vec<u8>> {
    if instruction.mnemonic != "b" || instruction.flow != FlowKind::Branch {
        return None;
    }
    let target = instruction.branch_target?;
    let delta = i64::try_from(target).ok()? - i64::try_from(instruction.address).ok()?;
    if delta % 4 != 0 {
        return None;
    }
    let imm26 = delta / 4;
    if !(-(1i64 << 25)..(1i64 << 25)).contains(&imm26) {
        return None;
    }
    let word = 0x1400_0000u32 | ((imm26 as u32) & 0x03ff_ffff);
    Some(word.to_le_bytes().to_vec())
}

fn parse_b_imm26(text: &str, address: u64) -> Option<Instruction> {
    let target = parse_absolute_target(text, "b")?;
    let delta = i64::try_from(target).ok()? - i64::try_from(address).ok()?;
    if delta % 4 != 0 {
        return None;
    }
    let imm26 = delta / 4;
    if !(-(1i64 << 25)..(1i64 << 25)).contains(&imm26) {
        return None;
    }
    let word = 0x1400_0000u32 | ((imm26 as u32) & 0x03ff_ffff);
    Some(Instruction {
        address,
        size: 4,
        bytes: word.to_le_bytes().to_vec(),
        mnemonic: "b".to_string(),
        operands: vec![Operand::AbsoluteAddress(target)],
        text: format!("b 0x{target:x}"),
        kind: InstructionKind::Branch,
        flow: FlowKind::Branch,
        branch_target: Some(target),
        status: DecodeStatus::Complete,
    })
}

fn parse_absolute_target(text: &str, mnemonic: &str) -> Option<u64> {
    let rest = text.trim().strip_prefix(mnemonic)?.trim();
    u64::from_str_radix(rest.strip_prefix("0x")?, 16).ok()
}
