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
    match first {
        0xc3 => Ok(base(
            vec![0xc3],
            address,
            "ret",
            Vec::new(),
            InstructionKind::Return,
            FlowKind::Return,
            None,
            DecodeStatus::Complete,
        )),
        0xe8 => {
            let disp = i64::from(read_i32(bytes, 1)?);
            let target = rel_target(address, 5, disp);
            Ok(base(
                bytes[..5].to_vec(),
                address,
                "call",
                absolute_target(target),
                InstructionKind::Call,
                FlowKind::Call,
                Some(target),
                DecodeStatus::Complete,
            ))
        }
        0xe9 => {
            let disp = i64::from(read_i32(bytes, 1)?);
            let target = rel_target(address, 5, disp);
            Ok(base(
                bytes[..5].to_vec(),
                address,
                "jmp",
                absolute_target(target),
                InstructionKind::Branch,
                FlowKind::Branch,
                Some(target),
                DecodeStatus::Complete,
            ))
        }
        0xeb => {
            let disp = i64::from(read_i8(bytes, 1)?);
            let target = rel_target(address, 2, disp);
            Ok(base(
                bytes[..2].to_vec(),
                address,
                "jmp",
                absolute_target(target),
                InstructionKind::Branch,
                FlowKind::Branch,
                Some(target),
                DecodeStatus::Complete,
            ))
        }
        0x70..=0x7f => {
            let disp = i64::from(read_i8(bytes, 1)?);
            let target = rel_target(address, 2, disp);
            Ok(base(
                bytes[..2].to_vec(),
                address,
                mnemonic_for_jcc(first),
                absolute_target(target),
                InstructionKind::Branch,
                FlowKind::ConditionalBranch,
                Some(target),
                DecodeStatus::Complete,
            ))
        }
        0x0f => {
            require_len(bytes, 2)?;
            let second = bytes[1];
            if (0x80..=0x8f).contains(&second) {
                let disp = i64::from(read_i32(bytes, 2)?);
                let target = rel_target(address, 6, disp);
                Ok(base(
                    bytes[..6].to_vec(),
                    address,
                    mnemonic_for_jcc(second),
                    absolute_target(target),
                    InstructionKind::Branch,
                    FlowKind::ConditionalBranch,
                    Some(target),
                    DecodeStatus::Complete,
                ))
            } else {
                Ok(unknown(first, address))
            }
        }
        _ => Ok(unknown(first, address)),
    }
}

fn require_len(bytes: &[u8], expected: usize) -> Result<()> {
    if bytes.len() < expected {
        return Err(DecodeError::TruncatedInstruction {
            expected,
            actual: bytes.len(),
        });
    }
    Ok(())
}

fn read_i8(bytes: &[u8], offset: usize) -> Result<i8> {
    require_len(bytes, offset + 1)?;
    Ok(bytes[offset] as i8)
}

fn read_i32(bytes: &[u8], offset: usize) -> Result<i32> {
    require_len(bytes, offset + 4)?;
    Ok(i32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ]))
}

fn rel_target(address: u64, size: usize, displacement: i64) -> u64 {
    address
        .wrapping_add(size as u64)
        .wrapping_add_signed(displacement)
}

fn absolute_target(target: u64) -> Vec<Operand> {
    vec![Operand::AbsoluteAddress(target)]
}

fn mnemonic_for_jcc(opcode: u8) -> &'static str {
    match opcode & 0x0f {
        0x0 => "jo",
        0x1 => "jno",
        0x2 => "jb",
        0x3 => "jae",
        0x4 => "je",
        0x5 => "jne",
        0x6 => "jbe",
        0x7 => "ja",
        0x8 => "js",
        0x9 => "jns",
        0xa => "jp",
        0xb => "jnp",
        0xc => "jl",
        0xd => "jge",
        0xe => "jle",
        _ => "jg",
    }
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
