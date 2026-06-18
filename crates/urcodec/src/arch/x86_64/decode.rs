use crate::{
    arch::x86_64::{
        format::render_instruction,
        registers::{reg32, reg64, reg8},
    },
    error::{DecodeError, Result},
    model::{DecodeStatus, FlowKind, Instruction, InstructionKind, MemoryOperand, Operand},
};

#[derive(Debug, Clone, Copy, Default)]
struct Rex {
    present: bool,
    w: bool,
    r: bool,
    x: bool,
    b: bool,
}

#[derive(Debug, Clone, Copy)]
struct Prefixes {
    rex: Rex,
    opcode_offset: usize,
}

#[derive(Debug, Clone, Copy)]
struct ModRm {
    mode: u8,
    reg: u8,
    rm: u8,
}

pub fn decode_instruction(bytes: &[u8], address: u64) -> Result<Instruction> {
    let prefixes = parse_prefixes(bytes)?;
    let opcode_offset = prefixes.opcode_offset;
    let opcode = bytes[opcode_offset];
    match opcode {
        0xc3 => Ok(base(
            bytes[..opcode_offset + 1].to_vec(),
            address,
            "ret",
            Vec::new(),
            InstructionKind::Return,
            FlowKind::Return,
            None,
        )),
        0xe8 => {
            let size = opcode_offset + 5;
            let disp = i64::from(read_i32(bytes, opcode_offset + 1)?);
            let target = rel_target(address, size, disp);
            Ok(base(
                bytes[..size].to_vec(),
                address,
                "call",
                absolute_target(target),
                InstructionKind::Call,
                FlowKind::Call,
                Some(target),
            ))
        }
        0xe9 => {
            let size = opcode_offset + 5;
            let disp = i64::from(read_i32(bytes, opcode_offset + 1)?);
            let target = rel_target(address, size, disp);
            Ok(base(
                bytes[..size].to_vec(),
                address,
                "jmp",
                absolute_target(target),
                InstructionKind::Branch,
                FlowKind::Branch,
                Some(target),
            ))
        }
        0xeb => {
            let size = opcode_offset + 2;
            let disp = i64::from(read_i8(bytes, opcode_offset + 1)?);
            let target = rel_target(address, size, disp);
            Ok(base(
                bytes[..size].to_vec(),
                address,
                "jmp",
                absolute_target(target),
                InstructionKind::Branch,
                FlowKind::Branch,
                Some(target),
            ))
        }
        0x70..=0x7f => {
            let size = opcode_offset + 2;
            let disp = i64::from(read_i8(bytes, opcode_offset + 1)?);
            let target = rel_target(address, size, disp);
            Ok(base(
                bytes[..size].to_vec(),
                address,
                mnemonic_for_jcc(opcode),
                absolute_target(target),
                InstructionKind::Branch,
                FlowKind::ConditionalBranch,
                Some(target),
            ))
        }
        0x0f => {
            require_len(bytes, opcode_offset + 2)?;
            let second = bytes[opcode_offset + 1];
            if (0x80..=0x8f).contains(&second) {
                let size = opcode_offset + 6;
                let disp = i64::from(read_i32(bytes, opcode_offset + 2)?);
                let target = rel_target(address, size, disp);
                Ok(base(
                    bytes[..size].to_vec(),
                    address,
                    mnemonic_for_jcc(second),
                    absolute_target(target),
                    InstructionKind::Branch,
                    FlowKind::ConditionalBranch,
                    Some(target),
                ))
            } else if second == 0x1f {
                decode_multibyte_nop(bytes, address, prefixes)
            } else if second == 0xb6 || second == 0xbe {
                decode_mov_extend(bytes, address, prefixes, second)
            } else {
                Ok(unknown(opcode, address))
            }
        }
        0xb8..=0xbf => {
            let reg = extend_reg(opcode - 0xb8, prefixes.rex.b);
            let (size, dst, imm) = if prefixes.rex.w {
                let size = opcode_offset + 9;
                require_len(bytes, size)?;
                let imm = u64::from_le_bytes([
                    bytes[opcode_offset + 1],
                    bytes[opcode_offset + 2],
                    bytes[opcode_offset + 3],
                    bytes[opcode_offset + 4],
                    bytes[opcode_offset + 5],
                    bytes[opcode_offset + 6],
                    bytes[opcode_offset + 7],
                    bytes[opcode_offset + 8],
                ]);
                (size, reg64(reg), imm)
            } else {
                let size = opcode_offset + 5;
                require_len(bytes, size)?;
                let imm = u32::from_le_bytes([
                    bytes[opcode_offset + 1],
                    bytes[opcode_offset + 2],
                    bytes[opcode_offset + 3],
                    bytes[opcode_offset + 4],
                ]);
                (size, reg32(reg), u64::from(imm))
            };
            Ok(base(
                bytes[..size].to_vec(),
                address,
                "mov",
                vec![Operand::Register(dst), Operand::Immediate(imm as i64)],
                InstructionKind::Move,
                FlowKind::Fallthrough,
                None,
            ))
        }
        0x89 | 0x8b | 0x8d => {
            let modrm_offset = opcode_offset + 1;
            require_len(bytes, modrm_offset + 1)?;
            let modrm = parse_modrm(bytes[modrm_offset]);
            let reg = Operand::Register(reg64(extend_reg(modrm.reg, prefixes.rex.r)));
            let (rm, consumed) = parse_rm_operand(bytes, modrm_offset, prefixes.rex, 64)?;
            let operands = match opcode {
                0x89 => vec![rm.clone(), reg],
                0x8b | 0x8d => vec![reg, rm.clone()],
                _ => Vec::new(),
            };
            let kind = match opcode {
                0x8d => InstructionKind::Address,
                0x89 if matches!(rm, Operand::Memory(_)) => InstructionKind::Store,
                0x8b if matches!(rm, Operand::Memory(_)) => InstructionKind::Load,
                _ => InstructionKind::Move,
            };
            Ok(base(
                bytes[..consumed].to_vec(),
                address,
                if opcode == 0x8d { "lea" } else { "mov" },
                operands,
                kind,
                FlowKind::Fallthrough,
                None,
            ))
        }
        0x01 => decode_reg_rm_binary(
            bytes,
            address,
            prefixes,
            "add",
            InstructionKind::Arithmetic,
            false,
        ),
        0x03 => decode_reg_rm_binary(
            bytes,
            address,
            prefixes,
            "add",
            InstructionKind::Arithmetic,
            true,
        ),
        0x29 => decode_reg_rm_binary(
            bytes,
            address,
            prefixes,
            "sub",
            InstructionKind::Arithmetic,
            false,
        ),
        0x2b => decode_reg_rm_binary(
            bytes,
            address,
            prefixes,
            "sub",
            InstructionKind::Arithmetic,
            true,
        ),
        0x21 => decode_reg_rm_binary(
            bytes,
            address,
            prefixes,
            "and",
            InstructionKind::Logical,
            false,
        ),
        0x23 => decode_reg_rm_binary(
            bytes,
            address,
            prefixes,
            "and",
            InstructionKind::Logical,
            true,
        ),
        0x09 => decode_reg_rm_binary(
            bytes,
            address,
            prefixes,
            "or",
            InstructionKind::Logical,
            false,
        ),
        0x0b => decode_reg_rm_binary(
            bytes,
            address,
            prefixes,
            "or",
            InstructionKind::Logical,
            true,
        ),
        0x31 => decode_reg_rm_binary(
            bytes,
            address,
            prefixes,
            "xor",
            InstructionKind::Logical,
            false,
        ),
        0x33 => decode_reg_rm_binary(
            bytes,
            address,
            prefixes,
            "xor",
            InstructionKind::Logical,
            true,
        ),
        0x39 => decode_reg_rm_binary(
            bytes,
            address,
            prefixes,
            "cmp",
            InstructionKind::Compare,
            false,
        ),
        0x3b => decode_reg_rm_binary(
            bytes,
            address,
            prefixes,
            "cmp",
            InstructionKind::Compare,
            true,
        ),
        0x85 => decode_reg_rm_binary(
            bytes,
            address,
            prefixes,
            "test",
            InstructionKind::Compare,
            false,
        ),
        0x83 => decode_group83(bytes, address, prefixes),
        0xf7 => decode_group_f7(bytes, address, prefixes),
        0x50..=0x57 => Ok(base(
            bytes[..prefixes.opcode_offset + 1].to_vec(),
            address,
            "push",
            vec![Operand::Register(reg64(extend_reg(
                opcode - 0x50,
                prefixes.rex.b,
            )))],
            InstructionKind::Store,
            FlowKind::Fallthrough,
            None,
        )),
        0x58..=0x5f => Ok(base(
            bytes[..prefixes.opcode_offset + 1].to_vec(),
            address,
            "pop",
            vec![Operand::Register(reg64(extend_reg(
                opcode - 0x58,
                prefixes.rex.b,
            )))],
            InstructionKind::Load,
            FlowKind::Fallthrough,
            None,
        )),
        _ => Ok(unknown(opcode, address)),
    }
}

fn decode_reg_rm_binary(
    bytes: &[u8],
    address: u64,
    prefixes: Prefixes,
    mnemonic: &str,
    kind: InstructionKind,
    reg_is_dst: bool,
) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 1;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let reg = Operand::Register(reg64(extend_reg(modrm.reg, prefixes.rex.r)));
    let (rm, consumed) = parse_rm_operand(bytes, modrm_offset, prefixes.rex, 64)?;
    let operands = if reg_is_dst {
        vec![reg, rm]
    } else {
        vec![rm, reg]
    };
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        mnemonic,
        operands,
        kind,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_group83(bytes: &[u8], address: u64, prefixes: Prefixes) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 1;
    require_len(bytes, modrm_offset + 2)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let (rm, consumed_without_imm) = parse_rm_operand(bytes, modrm_offset, prefixes.rex, 64)?;
    let imm = i64::from(read_i8(bytes, consumed_without_imm)?);
    let consumed = consumed_without_imm + 1;
    let (mnemonic, kind) = match modrm.reg {
        0 => ("add", InstructionKind::Arithmetic),
        1 => ("or", InstructionKind::Logical),
        2 => ("adc", InstructionKind::Arithmetic),
        3 => ("sbb", InstructionKind::Arithmetic),
        4 => ("and", InstructionKind::Logical),
        5 => ("sub", InstructionKind::Arithmetic),
        6 => ("xor", InstructionKind::Logical),
        7 => ("cmp", InstructionKind::Compare),
        _ => unreachable!("ModRM reg field is three bits"),
    };
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        mnemonic,
        vec![rm, Operand::Immediate(imm)],
        kind,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_group_f7(bytes: &[u8], address: u64, prefixes: Prefixes) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 1;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let (rm, consumed_without_imm) = parse_rm_operand(bytes, modrm_offset, prefixes.rex, 64)?;
    if modrm.reg <= 1 {
        let imm = i64::from(read_i32(bytes, consumed_without_imm)?);
        let consumed = consumed_without_imm + 4;
        return Ok(base(
            bytes[..consumed].to_vec(),
            address,
            "test",
            vec![rm, Operand::Immediate(imm)],
            InstructionKind::Compare,
            FlowKind::Fallthrough,
            None,
        ));
    }
    let (mnemonic, kind) = match modrm.reg {
        2 => ("not", InstructionKind::Logical),
        3 => ("neg", InstructionKind::Arithmetic),
        4 => ("mul", InstructionKind::Arithmetic),
        5 => ("imul", InstructionKind::Arithmetic),
        6 => ("div", InstructionKind::Arithmetic),
        7 => ("idiv", InstructionKind::Arithmetic),
        _ => unreachable!("ModRM reg field is three bits"),
    };
    Ok(base(
        bytes[..consumed_without_imm].to_vec(),
        address,
        mnemonic,
        vec![rm],
        kind,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_multibyte_nop(bytes: &[u8], address: u64, prefixes: Prefixes) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 2;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    if modrm.reg != 0 {
        return Ok(unknown(bytes[prefixes.opcode_offset], address));
    }
    let (_, consumed) = parse_rm_operand(bytes, modrm_offset, prefixes.rex, 64)?;
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        "nop",
        Vec::new(),
        InstructionKind::System,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_mov_extend(
    bytes: &[u8],
    address: u64,
    prefixes: Prefixes,
    opcode: u8,
) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 2;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let dst = Operand::Register(reg32(extend_reg(modrm.reg, prefixes.rex.r)));
    let (src, consumed) = if modrm.mode == 0b11 {
        (
            Operand::Register(reg8(
                extend_reg(modrm.rm, prefixes.rex.b),
                prefixes.rex.present,
            )),
            modrm_offset + 1,
        )
    } else {
        parse_rm_operand(bytes, modrm_offset, prefixes.rex, 8)?
    };
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        if opcode == 0xb6 { "movzx" } else { "movsx" },
        vec![dst, src.clone()],
        if matches!(src, Operand::Memory(_)) {
            InstructionKind::Load
        } else {
            InstructionKind::Move
        },
        FlowKind::Fallthrough,
        None,
    ))
}

fn parse_prefixes(bytes: &[u8]) -> Result<Prefixes> {
    require_len(bytes, 1)?;
    let mut offset = 0;
    let mut rex = Rex::default();
    while offset < bytes.len() {
        let byte = bytes[offset];
        if (0x40..=0x4f).contains(&byte) {
            rex = Rex {
                present: true,
                w: byte & 0x08 != 0,
                r: byte & 0x04 != 0,
                x: byte & 0x02 != 0,
                b: byte & 0x01 != 0,
            };
            offset += 1;
        } else {
            break;
        }
    }
    if offset >= bytes.len() {
        return Err(DecodeError::TruncatedInstruction {
            expected: offset + 1,
            actual: bytes.len(),
        });
    }
    Ok(Prefixes {
        rex,
        opcode_offset: offset,
    })
}

fn parse_modrm(byte: u8) -> ModRm {
    ModRm {
        mode: byte >> 6,
        reg: (byte >> 3) & 0x07,
        rm: byte & 0x07,
    }
}

fn extend_reg(index: u8, extension: bool) -> u8 {
    index | if extension { 8 } else { 0 }
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

fn read_i32_as_i64(bytes: &[u8], offset: usize) -> Result<i64> {
    Ok(i64::from(read_i32(bytes, offset)?))
}

fn parse_rm_operand(
    bytes: &[u8],
    modrm_offset: usize,
    rex: Rex,
    width_bits: u16,
) -> Result<(Operand, usize)> {
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let mut consumed = modrm_offset + 1;
    if modrm.mode == 0b11 {
        let reg = reg64(extend_reg(modrm.rm, rex.b));
        return Ok((Operand::Register(reg), consumed));
    }

    let mut base = None;
    let mut index = None;
    let mut scale = 1u8;
    let mut offset = 0i64;
    let mut relative = false;

    if modrm.rm == 0b100 {
        require_len(bytes, consumed + 1)?;
        let sib = bytes[consumed];
        consumed += 1;
        scale = 1u8 << (sib >> 6);
        let sib_index = (sib >> 3) & 0x07;
        let sib_base = sib & 0x07;
        if sib_index != 0b100 {
            index = Some(reg64(extend_reg(sib_index, rex.x)));
        }
        if modrm.mode == 0 && sib_base == 0b101 {
            offset = read_i32_as_i64(bytes, consumed)?;
            consumed += 4;
        } else {
            base = Some(reg64(extend_reg(sib_base, rex.b)));
        }
    } else if modrm.mode == 0 && modrm.rm == 0b101 {
        relative = true;
        base = Some(reg64(16));
        offset = read_i32_as_i64(bytes, consumed)?;
        consumed += 4;
    } else {
        base = Some(reg64(extend_reg(modrm.rm, rex.b)));
    }

    match modrm.mode {
        0 => {}
        1 => {
            offset = i64::from(read_i8(bytes, consumed)?);
            consumed += 1;
        }
        2 => {
            offset = read_i32_as_i64(bytes, consumed)?;
            consumed += 4;
        }
        _ => {}
    }

    let mut mem = if relative {
        MemoryOperand::rip_relative(offset, Some(width_bits))
    } else {
        MemoryOperand::indexed(base, index, scale, offset, Some(width_bits))
    };
    mem.relative = relative;
    Ok((Operand::Memory(mem), consumed))
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
        status: DecodeStatus::Complete,
    }
}

fn unknown(byte: u8, address: u64) -> Instruction {
    let mut instruction = base(
        vec![byte],
        address,
        ".byte",
        vec![Operand::Immediate(i64::from(byte))],
        InstructionKind::Unknown,
        FlowKind::Fallthrough,
        None,
    );
    instruction.status = DecodeStatus::Unknown;
    instruction
}
