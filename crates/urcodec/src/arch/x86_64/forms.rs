use crate::{
    error::{EncodeError, TextError},
    form::{FormId, InstructionForm},
    model::{Architecture, DecodeStatus, FlowKind, Instruction, InstructionKind, Operand},
};

static FORMS: &[InstructionForm] = &[
    InstructionForm::new(
        FormId::new(Architecture::X86_64, "ret"),
        "ret",
        InstructionKind::Return,
        FlowKind::Return,
        encode_ret,
        parse_ret,
    ),
    InstructionForm::new(
        FormId::new(Architecture::X86_64, "call_rel32"),
        "call",
        InstructionKind::Call,
        FlowKind::Call,
        encode_call_rel32,
        parse_call_rel32,
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
        .then(|| vec![0xc3])
}

fn parse_ret(text: &str, address: u64) -> Option<Instruction> {
    (text.trim() == "ret").then(|| Instruction {
        address,
        size: 1,
        bytes: vec![0xc3],
        mnemonic: "ret".to_string(),
        operands: Vec::new(),
        text: "ret".to_string(),
        kind: InstructionKind::Return,
        flow: FlowKind::Return,
        branch_target: None,
        status: DecodeStatus::Complete,
    })
}

fn encode_call_rel32(instruction: &Instruction) -> Option<Vec<u8>> {
    if instruction.mnemonic != "call" || instruction.flow != FlowKind::Call {
        return None;
    }
    let target = instruction.branch_target?;
    let next = instruction.address.checked_add(5)?;
    let disp = i64::try_from(target).ok()? - i64::try_from(next).ok()?;
    let disp = i32::try_from(disp).ok()?;
    let mut out = vec![0xe8];
    out.extend_from_slice(&disp.to_le_bytes());
    Some(out)
}

fn parse_call_rel32(text: &str, address: u64) -> Option<Instruction> {
    let target = parse_absolute_target(text, "call")?;
    let next = address.checked_add(5)?;
    let disp = i64::try_from(target).ok()? - i64::try_from(next).ok()?;
    let disp = i32::try_from(disp).ok()?;
    let mut bytes = vec![0xe8];
    bytes.extend_from_slice(&disp.to_le_bytes());
    Some(Instruction {
        address,
        size: 5,
        bytes,
        mnemonic: "call".to_string(),
        operands: vec![Operand::AbsoluteAddress(target)],
        text: format!("call 0x{target:x}"),
        kind: InstructionKind::Call,
        flow: FlowKind::Call,
        branch_target: Some(target),
        status: DecodeStatus::Complete,
    })
}

fn parse_absolute_target(text: &str, mnemonic: &str) -> Option<u64> {
    let rest = text.trim().strip_prefix(mnemonic)?.trim();
    u64::from_str_radix(rest.strip_prefix("0x")?, 16).ok()
}
