use crate::{
    arch::x86_64::format::render_instruction,
    error::{DecodeError, Result},
    model::{DecodeStatus, FlowKind, Instruction, InstructionKind, Operand},
};

pub fn decode_instruction(bytes: &[u8], address: u64) -> Result<Instruction> {
    let first = *bytes.first().ok_or(DecodeError::TruncatedInstruction {
        expected: 1,
        actual: 0,
    })?;
    Ok(unknown(first, address))
}

fn base(
    bytes: Vec<u8>,
    address: u64,
    mnemonic: &str,
    operands: Vec<Operand>,
    kind: InstructionKind,
    flow: FlowKind,
    branch_target: Option<u64>,
    status: DecodeStatus,
) -> Instruction {
    Instruction {
        address,
        size: bytes.len() as u8,
        bytes,
        mnemonic: mnemonic.to_string(),
        text: render_instruction(mnemonic, &operands),
        operands,
        kind,
        flow,
        branch_target,
        status,
    }
}

fn unknown(byte: u8, address: u64) -> Instruction {
    base(
        vec![byte],
        address,
        ".byte",
        vec![Operand::Immediate(i64::from(byte))],
        InstructionKind::Unknown,
        FlowKind::Fallthrough,
        None,
        DecodeStatus::Unknown,
    )
}
