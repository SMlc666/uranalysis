use crate::{
    arch::x86_64::{format::render_instruction, registers::reg64},
    error::{DecodeError, EncodeError, TextError},
    form::{FormId, InstructionForm},
    model::{Architecture, DecodeStatus, FlowKind, Instruction, InstructionKind, Operand},
};

static FORMS: &[InstructionForm] = &[
    InstructionForm::new(
        FormId::new(Architecture::X86_64, "ret"),
        "ret",
        InstructionKind::Return,
        FlowKind::Return,
        decode_ret,
        encode_ret,
        parse_ret,
    ),
    InstructionForm::new(
        FormId::new(Architecture::X86_64, "ret_imm16"),
        "ret",
        InstructionKind::Return,
        FlowKind::Return,
        decode_ret_imm16,
        encode_ret_imm16,
        parse_ret_imm16,
    ),
    InstructionForm::new(
        FormId::new(Architecture::X86_64, "retf"),
        "retf",
        InstructionKind::Return,
        FlowKind::Return,
        decode_retf,
        encode_retf,
        parse_retf,
    ),
    InstructionForm::new(
        FormId::new(Architecture::X86_64, "call_rel32"),
        "call",
        InstructionKind::Call,
        FlowKind::Call,
        decode_call_rel32,
        encode_call_rel32,
        parse_call_rel32,
    ),
    InstructionForm::new(
        FormId::new(Architecture::X86_64, "call_rm64"),
        "call",
        InstructionKind::Call,
        FlowKind::IndirectCall,
        decode_call_rm64,
        encode_call_rm64,
        parse_call_rm64,
    ),
    InstructionForm::new(
        FormId::new(Architecture::X86_64, "jmp_rel8"),
        "jmp",
        InstructionKind::Branch,
        FlowKind::Branch,
        decode_jmp_rel8,
        encode_jmp_rel8,
        parse_jmp_rel8,
    ),
    InstructionForm::new(
        FormId::new(Architecture::X86_64, "jmp_rel32"),
        "jmp",
        InstructionKind::Branch,
        FlowKind::Branch,
        decode_jmp_rel32,
        encode_jmp_rel32,
        parse_jmp_rel32,
    ),
    InstructionForm::new(
        FormId::new(Architecture::X86_64, "jmp_rm64"),
        "jmp",
        InstructionKind::Branch,
        FlowKind::IndirectBranch,
        decode_jmp_rm64,
        encode_jmp_rm64,
        parse_jmp_rm64,
    ),
    InstructionForm::new(
        FormId::new(Architecture::X86_64, "jcc_rel8"),
        "jcc",
        InstructionKind::Branch,
        FlowKind::ConditionalBranch,
        decode_jcc_rel8,
        encode_jcc_rel8,
        parse_jcc_rel8,
    ),
    InstructionForm::new(
        FormId::new(Architecture::X86_64, "jcc_rel32"),
        "jcc",
        InstructionKind::Branch,
        FlowKind::ConditionalBranch,
        decode_jcc_rel32,
        encode_jcc_rel32,
        parse_jcc_rel32,
    ),
    InstructionForm::new(
        FormId::new(Architecture::X86_64, "loopne_rel8"),
        "loopne",
        InstructionKind::Branch,
        FlowKind::ConditionalBranch,
        decode_loopne,
        encode_loopne,
        parse_loopne,
    ),
    InstructionForm::new(
        FormId::new(Architecture::X86_64, "loope_rel8"),
        "loope",
        InstructionKind::Branch,
        FlowKind::ConditionalBranch,
        decode_loope,
        encode_loope,
        parse_loope,
    ),
    InstructionForm::new(
        FormId::new(Architecture::X86_64, "loop_rel8"),
        "loop",
        InstructionKind::Branch,
        FlowKind::ConditionalBranch,
        decode_loop,
        encode_loop,
        parse_loop,
    ),
    InstructionForm::new(
        FormId::new(Architecture::X86_64, "jrcxz_rel8"),
        "jrcxz",
        InstructionKind::Branch,
        FlowKind::ConditionalBranch,
        decode_jrcxz,
        encode_jrcxz,
        parse_jrcxz,
    ),
    InstructionForm::new(
        FormId::new(Architecture::X86_64, "mov_r64_imm64"),
        "mov",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        decode_mov_r64_imm64,
        encode_mov_r64_imm64,
        parse_mov_r64_imm64,
    ),
];

pub fn all_forms() -> &'static [InstructionForm] {
    FORMS
}

pub fn decode(bytes: &[u8], address: u64) -> Result<Option<Instruction>, DecodeError> {
    for form in FORMS {
        if let Some(instruction) = form.decode(bytes, address)? {
            return Ok(Some(instruction));
        }
    }
    Ok(None)
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

fn decode_ret(bytes: &[u8], address: u64) -> Result<Option<Instruction>, DecodeError> {
    Ok((bytes.first().copied() == Some(0xc3)).then(|| {
        base(
            vec![0xc3],
            address,
            "ret",
            Vec::new(),
            InstructionKind::Return,
            FlowKind::Return,
            None,
        )
    }))
}

fn decode_ret_imm16(bytes: &[u8], address: u64) -> Result<Option<Instruction>, DecodeError> {
    if bytes.first().copied() != Some(0xc2) {
        return Ok(None);
    }
    require_len(bytes, 3)?;
    let imm = i64::from(u16::from_le_bytes([bytes[1], bytes[2]]));
    Ok(Some(base(
        bytes[..3].to_vec(),
        address,
        "ret",
        vec![Operand::Immediate(imm)],
        InstructionKind::Return,
        FlowKind::Return,
        None,
    )))
}

fn decode_retf(bytes: &[u8], address: u64) -> Result<Option<Instruction>, DecodeError> {
    match bytes.first().copied() {
        Some(0xcb) => Ok(Some(base(
            vec![0xcb],
            address,
            "retf",
            Vec::new(),
            InstructionKind::Return,
            FlowKind::Return,
            None,
        ))),
        Some(0xca) => {
            require_len(bytes, 3)?;
            let imm = i64::from(u16::from_le_bytes([bytes[1], bytes[2]]));
            Ok(Some(base(
                bytes[..3].to_vec(),
                address,
                "retf",
                vec![Operand::Immediate(imm)],
                InstructionKind::Return,
                FlowKind::Return,
                None,
            )))
        }
        _ => Ok(None),
    }
}

fn decode_call_rel32(bytes: &[u8], address: u64) -> Result<Option<Instruction>, DecodeError> {
    decode_rel32(
        bytes,
        address,
        0xe8,
        "call",
        InstructionKind::Call,
        FlowKind::Call,
    )
}

fn decode_call_rm64(bytes: &[u8], address: u64) -> Result<Option<Instruction>, DecodeError> {
    decode_group_ff_register(
        bytes,
        address,
        2,
        "call",
        InstructionKind::Call,
        FlowKind::IndirectCall,
    )
}

fn decode_jmp_rel32(bytes: &[u8], address: u64) -> Result<Option<Instruction>, DecodeError> {
    decode_rel32(
        bytes,
        address,
        0xe9,
        "jmp",
        InstructionKind::Branch,
        FlowKind::Branch,
    )
}

fn decode_jmp_rm64(bytes: &[u8], address: u64) -> Result<Option<Instruction>, DecodeError> {
    decode_group_ff_register(
        bytes,
        address,
        4,
        "jmp",
        InstructionKind::Branch,
        FlowKind::IndirectBranch,
    )
}

fn decode_jmp_rel8(bytes: &[u8], address: u64) -> Result<Option<Instruction>, DecodeError> {
    decode_rel8(
        bytes,
        address,
        0xeb,
        "jmp",
        InstructionKind::Branch,
        FlowKind::Branch,
    )
}

fn decode_jcc_rel8(bytes: &[u8], address: u64) -> Result<Option<Instruction>, DecodeError> {
    let Some(opcode) = bytes.first().copied() else {
        return Ok(None);
    };
    if !(0x70..=0x7f).contains(&opcode) {
        return Ok(None);
    }
    require_len(bytes, 2)?;
    let disp = i64::from(i8::from_le_bytes([bytes[1]]));
    let target = rel_target(address, 2, disp);
    let mnemonic = mnemonic_for_jcc(opcode & 0x0f);
    Ok(Some(base(
        bytes[..2].to_vec(),
        address,
        mnemonic,
        vec![Operand::AbsoluteAddress(target)],
        InstructionKind::Branch,
        FlowKind::ConditionalBranch,
        Some(target),
    )))
}

fn decode_group_ff_register(
    bytes: &[u8],
    address: u64,
    reg_opcode: u8,
    mnemonic: &str,
    kind: InstructionKind,
    flow: FlowKind,
) -> Result<Option<Instruction>, DecodeError> {
    let Some(first) = bytes.first().copied() else {
        return Ok(None);
    };
    let (rex, opcode_offset) = if first & 0xf0 == 0x40 {
        require_len(bytes, 2)?;
        (first, 1)
    } else {
        (0, 0)
    };
    if bytes[opcode_offset] != 0xff {
        return Ok(None);
    }
    require_len(bytes, opcode_offset + 2)?;
    let modrm = bytes[opcode_offset + 1];
    if modrm & 0xc0 != 0xc0 || ((modrm >> 3) & 0x07) != reg_opcode {
        return Ok(None);
    }
    let index = (modrm & 0x07) | if rex & 0x01 != 0 { 8 } else { 0 };
    Ok(Some(base(
        bytes[..opcode_offset + 2].to_vec(),
        address,
        mnemonic,
        vec![Operand::Register(reg64(index))],
        kind,
        flow,
        None,
    )))
}

fn decode_jcc_rel32(bytes: &[u8], address: u64) -> Result<Option<Instruction>, DecodeError> {
    let Some(first) = bytes.first().copied() else {
        return Ok(None);
    };
    if first != 0x0f {
        return Ok(None);
    }
    require_len(bytes, 2)?;
    let second = bytes[1];
    if !(0x80..=0x8f).contains(&second) {
        return Ok(None);
    }
    require_len(bytes, 6)?;
    let disp = i64::from(i32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]));
    let target = rel_target(address, 6, disp);
    let mnemonic = mnemonic_for_jcc(second & 0x0f);
    Ok(Some(base(
        bytes[..6].to_vec(),
        address,
        mnemonic,
        vec![Operand::AbsoluteAddress(target)],
        InstructionKind::Branch,
        FlowKind::ConditionalBranch,
        Some(target),
    )))
}

fn decode_rel32(
    bytes: &[u8],
    address: u64,
    opcode: u8,
    mnemonic: &str,
    kind: InstructionKind,
    flow: FlowKind,
) -> Result<Option<Instruction>, DecodeError> {
    if bytes.first().copied() != Some(opcode) {
        return Ok(None);
    }
    require_len(bytes, 5)?;
    let disp = i64::from(i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]));
    let target = rel_target(address, 5, disp);
    Ok(Some(base(
        bytes[..5].to_vec(),
        address,
        mnemonic,
        vec![Operand::AbsoluteAddress(target)],
        kind,
        flow,
        Some(target),
    )))
}

fn decode_rel8(
    bytes: &[u8],
    address: u64,
    opcode: u8,
    mnemonic: &str,
    kind: InstructionKind,
    flow: FlowKind,
) -> Result<Option<Instruction>, DecodeError> {
    if bytes.first().copied() != Some(opcode) {
        return Ok(None);
    }
    require_len(bytes, 2)?;
    let disp = i64::from(i8::from_le_bytes([bytes[1]]));
    let target = rel_target(address, 2, disp);
    Ok(Some(base(
        bytes[..2].to_vec(),
        address,
        mnemonic,
        vec![Operand::AbsoluteAddress(target)],
        kind,
        flow,
        Some(target),
    )))
}

fn decode_loopne(bytes: &[u8], address: u64) -> Result<Option<Instruction>, DecodeError> {
    decode_loop_family(bytes, address, 0xe0, "loopne")
}

fn decode_loope(bytes: &[u8], address: u64) -> Result<Option<Instruction>, DecodeError> {
    decode_loop_family(bytes, address, 0xe1, "loope")
}

fn decode_loop(bytes: &[u8], address: u64) -> Result<Option<Instruction>, DecodeError> {
    decode_loop_family(bytes, address, 0xe2, "loop")
}

fn decode_jrcxz(bytes: &[u8], address: u64) -> Result<Option<Instruction>, DecodeError> {
    decode_loop_family(bytes, address, 0xe3, "jrcxz")
}

fn decode_loop_family(
    bytes: &[u8],
    address: u64,
    opcode: u8,
    mnemonic: &str,
) -> Result<Option<Instruction>, DecodeError> {
    decode_rel8(
        bytes,
        address,
        opcode,
        mnemonic,
        InstructionKind::Branch,
        FlowKind::ConditionalBranch,
    )
}

fn decode_mov_r64_imm64(bytes: &[u8], address: u64) -> Result<Option<Instruction>, DecodeError> {
    let Some(rex) = bytes.first().copied() else {
        return Ok(None);
    };
    if rex & 0xf8 != 0x48 {
        return Ok(None);
    }
    require_len(bytes, 2)?;
    let opcode = bytes[1];
    if !(0xb8..=0xbf).contains(&opcode) {
        return Ok(None);
    }
    require_len(bytes, 10)?;
    let index = (opcode - 0xb8) | if rex & 0x01 != 0 { 8 } else { 0 };
    let imm = i64::from_le_bytes(bytes[2..10].try_into().ok().unwrap());
    Ok(Some(base(
        bytes[..10].to_vec(),
        address,
        "mov",
        vec![Operand::Register(reg64(index)), Operand::Immediate(imm)],
        InstructionKind::Move,
        FlowKind::Fallthrough,
        None,
    )))
}

fn encode_ret(instruction: &Instruction) -> Option<Vec<u8>> {
    (instruction.mnemonic == "ret"
        && instruction.operands.is_empty()
        && instruction.flow == FlowKind::Return)
        .then(|| vec![0xc3])
}

fn encode_ret_imm16(instruction: &Instruction) -> Option<Vec<u8>> {
    if instruction.mnemonic != "ret" || instruction.flow != FlowKind::Return {
        return None;
    }
    let [Operand::Immediate(imm)] = instruction.operands.as_slice() else {
        return None;
    };
    let imm = u16::try_from(*imm).ok()?;
    let mut out = vec![0xc2];
    out.extend_from_slice(&imm.to_le_bytes());
    Some(out)
}

fn parse_ret(text: &str, address: u64) -> Option<Instruction> {
    (text.trim() == "ret").then(|| {
        base(
            vec![0xc3],
            address,
            "ret",
            Vec::new(),
            InstructionKind::Return,
            FlowKind::Return,
            None,
        )
    })
}

fn parse_ret_imm16(text: &str, address: u64) -> Option<Instruction> {
    let imm = parse_prefixed_u16(text, "ret")?;
    let mut bytes = vec![0xc2];
    bytes.extend_from_slice(&imm.to_le_bytes());
    Some(base(
        bytes,
        address,
        "ret",
        vec![Operand::Immediate(i64::from(imm))],
        InstructionKind::Return,
        FlowKind::Return,
        None,
    ))
}

fn encode_retf(instruction: &Instruction) -> Option<Vec<u8>> {
    if instruction.mnemonic != "retf" || instruction.flow != FlowKind::Return {
        return None;
    }
    match instruction.operands.as_slice() {
        [] => Some(vec![0xcb]),
        [Operand::Immediate(imm)] => {
            let imm = u16::try_from(*imm).ok()?;
            let mut out = vec![0xca];
            out.extend_from_slice(&imm.to_le_bytes());
            Some(out)
        }
        _ => None,
    }
}

fn parse_retf(text: &str, address: u64) -> Option<Instruction> {
    let trimmed = text.trim();
    if trimmed == "retf" {
        return Some(base(
            vec![0xcb],
            address,
            "retf",
            Vec::new(),
            InstructionKind::Return,
            FlowKind::Return,
            None,
        ));
    }
    let imm = parse_prefixed_u16(trimmed, "retf")?;
    let mut bytes = vec![0xca];
    bytes.extend_from_slice(&imm.to_le_bytes());
    Some(base(
        bytes,
        address,
        "retf",
        vec![Operand::Immediate(i64::from(imm))],
        InstructionKind::Return,
        FlowKind::Return,
        None,
    ))
}

fn encode_call_rel32(instruction: &Instruction) -> Option<Vec<u8>> {
    if instruction.mnemonic != "call" || instruction.flow != FlowKind::Call {
        return None;
    }
    let target = extract_branch_target(instruction)?;
    let disp = rel32_displacement(instruction.address, 5, target)?;
    let mut out = vec![0xe8];
    out.extend_from_slice(&disp.to_le_bytes());
    Some(out)
}

fn parse_call_rel32(text: &str, address: u64) -> Option<Instruction> {
    let target = parse_absolute_target(text, "call")?;
    let disp = rel32_displacement(address, 5, target)?;
    let mut bytes = vec![0xe8];
    bytes.extend_from_slice(&disp.to_le_bytes());
    Some(base(
        bytes,
        address,
        "call",
        vec![Operand::AbsoluteAddress(target)],
        InstructionKind::Call,
        FlowKind::Call,
        Some(target),
    ))
}

fn encode_call_rm64(instruction: &Instruction) -> Option<Vec<u8>> {
    encode_group_ff_register(instruction, "call", 2, FlowKind::IndirectCall)
}

fn parse_call_rm64(text: &str, address: u64) -> Option<Instruction> {
    parse_group_ff_register(
        text,
        address,
        "call",
        2,
        InstructionKind::Call,
        FlowKind::IndirectCall,
    )
}

fn encode_loopne(instruction: &Instruction) -> Option<Vec<u8>> {
    encode_loop_instruction(instruction, "loopne", 0xe0)
}

fn parse_loopne(text: &str, address: u64) -> Option<Instruction> {
    parse_loop_instruction(text, address, "loopne", 0xe0)
}

fn encode_loope(instruction: &Instruction) -> Option<Vec<u8>> {
    encode_loop_instruction(instruction, "loope", 0xe1)
}

fn parse_loope(text: &str, address: u64) -> Option<Instruction> {
    parse_loop_instruction(text, address, "loope", 0xe1)
}

fn encode_loop(instruction: &Instruction) -> Option<Vec<u8>> {
    encode_loop_instruction(instruction, "loop", 0xe2)
}

fn parse_loop(text: &str, address: u64) -> Option<Instruction> {
    parse_loop_instruction(text, address, "loop", 0xe2)
}

fn encode_jrcxz(instruction: &Instruction) -> Option<Vec<u8>> {
    encode_loop_instruction(instruction, "jrcxz", 0xe3)
}

fn parse_jrcxz(text: &str, address: u64) -> Option<Instruction> {
    parse_loop_instruction(text, address, "jrcxz", 0xe3)
}

fn encode_loop_instruction(
    instruction: &Instruction,
    mnemonic: &str,
    opcode: u8,
) -> Option<Vec<u8>> {
    if instruction.mnemonic != mnemonic || instruction.flow != FlowKind::ConditionalBranch {
        return None;
    }
    let target = extract_conditional_target(instruction)?;
    let disp = rel8_displacement(instruction.address, 2, target)?;
    Some(vec![opcode, disp as u8])
}

fn parse_loop_instruction(
    text: &str,
    address: u64,
    mnemonic: &str,
    opcode: u8,
) -> Option<Instruction> {
    let target = parse_absolute_target(text, mnemonic)?;
    let disp = rel8_displacement(address, 2, target)?;
    Some(base(
        vec![opcode, disp as u8],
        address,
        mnemonic,
        vec![Operand::AbsoluteAddress(target)],
        InstructionKind::Branch,
        FlowKind::ConditionalBranch,
        Some(target),
    ))
}

fn encode_mov_r64_imm64(instruction: &Instruction) -> Option<Vec<u8>> {
    if instruction.mnemonic != "mov" || instruction.flow != FlowKind::Fallthrough {
        return None;
    }
    let [Operand::Register(reg), Operand::Immediate(imm)] = instruction.operands.as_slice() else {
        return None;
    };
    let index = parse_r64_register(&reg.name)?;
    let rex = 0x48 | if index >= 8 { 0x01 } else { 0x00 };
    let opcode = 0xb8 | (index & 0x07);
    let mut out = vec![rex, opcode];
    out.extend_from_slice(&imm.to_le_bytes());
    Some(out)
}

fn parse_mov_r64_imm64(text: &str, address: u64) -> Option<Instruction> {
    let rest = text.trim().strip_prefix("mov")?.trim();
    let (reg_text, imm_text) = rest.split_once(',')?;
    let index = parse_r64_register(reg_text.trim())?;
    let imm = parse_u64_hex(imm_text.trim())? as i64;
    let mut bytes = vec![
        0x48 | if index >= 8 { 0x01 } else { 0x00 },
        0xb8 | (index & 0x07),
    ];
    bytes.extend_from_slice(&imm.to_le_bytes());
    Some(base(
        bytes,
        address,
        "mov",
        vec![Operand::Register(reg64(index)), Operand::Immediate(imm)],
        InstructionKind::Move,
        FlowKind::Fallthrough,
        None,
    ))
}

fn encode_jmp_rel8(instruction: &Instruction) -> Option<Vec<u8>> {
    encode_jump_rel8(instruction, "jmp")
}

fn parse_jmp_rel8(text: &str, address: u64) -> Option<Instruction> {
    parse_jump_rel8(text, address, "jmp")
}

fn encode_jmp_rel32(instruction: &Instruction) -> Option<Vec<u8>> {
    encode_jump_rel32(instruction, "jmp")
}

fn parse_jmp_rel32(text: &str, address: u64) -> Option<Instruction> {
    parse_jump_rel32(text, address, "jmp")
}

fn encode_jmp_rm64(instruction: &Instruction) -> Option<Vec<u8>> {
    encode_group_ff_register(instruction, "jmp", 4, FlowKind::IndirectBranch)
}

fn parse_jmp_rm64(text: &str, address: u64) -> Option<Instruction> {
    parse_group_ff_register(
        text,
        address,
        "jmp",
        4,
        InstructionKind::Branch,
        FlowKind::IndirectBranch,
    )
}

fn encode_jcc_rel8(instruction: &Instruction) -> Option<Vec<u8>> {
    let opcode_low = jcc_opcode_low(&instruction.mnemonic)?;
    let target = extract_conditional_target(instruction)?;
    let disp = rel8_displacement(instruction.address, 2, target)?;
    Some(vec![0x70 | opcode_low, disp as u8])
}

fn parse_jcc_rel8(text: &str, address: u64) -> Option<Instruction> {
    let (mnemonic, target) = parse_jump_text(text)?;
    let opcode_low = jcc_opcode_low(mnemonic)?;
    let disp = rel8_displacement(address, 2, target)?;
    Some(base(
        vec![0x70 | opcode_low, disp as u8],
        address,
        mnemonic,
        vec![Operand::AbsoluteAddress(target)],
        InstructionKind::Branch,
        FlowKind::ConditionalBranch,
        Some(target),
    ))
}

fn encode_group_ff_register(
    instruction: &Instruction,
    mnemonic: &str,
    reg_opcode: u8,
    flow: FlowKind,
) -> Option<Vec<u8>> {
    if instruction.mnemonic != mnemonic || instruction.flow != flow {
        return None;
    }
    let [Operand::Register(reg)] = instruction.operands.as_slice() else {
        return None;
    };
    let index = parse_r64_register(&reg.name)?;
    Some(vec![
        0x48 | if index >= 8 { 0x01 } else { 0x00 },
        0xff,
        0xc0 | (reg_opcode << 3) | (index & 0x07),
    ])
}

fn parse_group_ff_register(
    text: &str,
    address: u64,
    mnemonic: &str,
    reg_opcode: u8,
    kind: InstructionKind,
    flow: FlowKind,
) -> Option<Instruction> {
    let reg_text = text.trim().strip_prefix(mnemonic)?.trim();
    let index = parse_r64_register(reg_text)?;
    let bytes = vec![
        0x48 | if index >= 8 { 0x01 } else { 0x00 },
        0xff,
        0xc0 | (reg_opcode << 3) | (index & 0x07),
    ];
    Some(base(
        bytes,
        address,
        mnemonic,
        vec![Operand::Register(reg64(index))],
        kind,
        flow,
        None,
    ))
}

fn encode_jcc_rel32(instruction: &Instruction) -> Option<Vec<u8>> {
    let opcode_low = jcc_opcode_low(&instruction.mnemonic)?;
    let target = extract_conditional_target(instruction)?;
    let disp = rel32_displacement(instruction.address, 6, target)?;
    let mut out = vec![0x0f, 0x80 | opcode_low];
    out.extend_from_slice(&disp.to_le_bytes());
    Some(out)
}

fn parse_jcc_rel32(text: &str, address: u64) -> Option<Instruction> {
    let (mnemonic, target) = parse_jump_text(text)?;
    let opcode_low = jcc_opcode_low(mnemonic)?;
    let disp = rel32_displacement(address, 6, target)?;
    let mut bytes = vec![0x0f, 0x80 | opcode_low];
    bytes.extend_from_slice(&disp.to_le_bytes());
    Some(base(
        bytes,
        address,
        mnemonic,
        vec![Operand::AbsoluteAddress(target)],
        InstructionKind::Branch,
        FlowKind::ConditionalBranch,
        Some(target),
    ))
}

fn encode_jump_rel8(instruction: &Instruction, mnemonic: &str) -> Option<Vec<u8>> {
    if instruction.mnemonic != mnemonic || instruction.flow != FlowKind::Branch {
        return None;
    }
    let target = extract_branch_target(instruction)?;
    let disp = rel8_displacement(instruction.address, 2, target)?;
    Some(vec![0xeb, disp as u8])
}

fn parse_jump_rel8(text: &str, address: u64, mnemonic: &str) -> Option<Instruction> {
    let target = parse_absolute_target(text, mnemonic)?;
    let disp = rel8_displacement(address, 2, target)?;
    Some(base(
        vec![0xeb, disp as u8],
        address,
        mnemonic,
        vec![Operand::AbsoluteAddress(target)],
        InstructionKind::Branch,
        FlowKind::Branch,
        Some(target),
    ))
}

fn encode_jump_rel32(instruction: &Instruction, mnemonic: &str) -> Option<Vec<u8>> {
    if instruction.mnemonic != mnemonic || instruction.flow != FlowKind::Branch {
        return None;
    }
    let target = extract_branch_target(instruction)?;
    let disp = rel32_displacement(instruction.address, 5, target)?;
    let mut bytes = vec![0xe9];
    bytes.extend_from_slice(&disp.to_le_bytes());
    Some(bytes)
}

fn parse_jump_rel32(text: &str, address: u64, mnemonic: &str) -> Option<Instruction> {
    let target = parse_absolute_target(text, mnemonic)?;
    let disp = rel32_displacement(address, 5, target)?;
    let mut bytes = vec![0xe9];
    bytes.extend_from_slice(&disp.to_le_bytes());
    Some(base(
        bytes,
        address,
        mnemonic,
        vec![Operand::AbsoluteAddress(target)],
        InstructionKind::Branch,
        FlowKind::Branch,
        Some(target),
    ))
}

fn require_len(bytes: &[u8], expected: usize) -> Result<(), DecodeError> {
    if bytes.len() < expected {
        return Err(DecodeError::TruncatedInstruction {
            expected,
            actual: bytes.len(),
        });
    }
    Ok(())
}

fn rel_target(address: u64, size: usize, displacement: i64) -> u64 {
    address
        .wrapping_add(size as u64)
        .wrapping_add_signed(displacement)
}

fn rel8_displacement(address: u64, size: usize, target: u64) -> Option<i8> {
    let disp =
        i64::try_from(target).ok()? - i64::try_from(address.wrapping_add(size as u64)).ok()?;
    i8::try_from(disp).ok()
}

fn rel32_displacement(address: u64, size: usize, target: u64) -> Option<i32> {
    let disp =
        i64::try_from(target).ok()? - i64::try_from(address.wrapping_add(size as u64)).ok()?;
    i32::try_from(disp).ok()
}

fn extract_branch_target(instruction: &Instruction) -> Option<u64> {
    instruction.branch_target.or_else(|| {
        instruction
            .operands
            .iter()
            .find_map(|operand| match operand {
                Operand::AbsoluteAddress(addr) => Some(*addr),
                _ => None,
            })
    })
}

fn extract_conditional_target(instruction: &Instruction) -> Option<u64> {
    (instruction.flow == FlowKind::ConditionalBranch)
        .then_some(())
        .and_then(|_| extract_branch_target(instruction))
}

fn parse_absolute_target(text: &str, mnemonic: &str) -> Option<u64> {
    let rest = text.trim().strip_prefix(mnemonic)?.trim();
    parse_target_text(rest)
}

fn parse_jump_text(text: &str) -> Option<(&str, u64)> {
    let (mnemonic, target) = text.trim().split_once(' ')?;
    Some((mnemonic, parse_target_text(target.trim())?))
}

fn parse_target_text(text: &str) -> Option<u64> {
    u64::from_str_radix(text.strip_prefix("0x")?, 16).ok()
}

fn parse_u64_hex(text: &str) -> Option<u64> {
    u64::from_str_radix(text.strip_prefix("0x")?, 16).ok()
}

fn parse_prefixed_u16(text: &str, mnemonic: &str) -> Option<u16> {
    let rest = text.trim().strip_prefix(mnemonic)?.trim();
    u16::try_from(parse_u64_hex(rest)?).ok()
}

fn parse_r64_register(name: &str) -> Option<u8> {
    Some(match name {
        "rax" => 0,
        "rcx" => 1,
        "rdx" => 2,
        "rbx" => 3,
        "rsp" => 4,
        "rbp" => 5,
        "rsi" => 6,
        "rdi" => 7,
        "r8" => 8,
        "r9" => 9,
        "r10" => 10,
        "r11" => 11,
        "r12" => 12,
        "r13" => 13,
        "r14" => 14,
        "r15" => 15,
        _ => return None,
    })
}

fn jcc_opcode_low(mnemonic: &str) -> Option<u8> {
    Some(match mnemonic {
        "jo" => 0x0,
        "jno" => 0x1,
        "jb" => 0x2,
        "jae" => 0x3,
        "je" => 0x4,
        "jne" => 0x5,
        "jbe" => 0x6,
        "ja" => 0x7,
        "js" => 0x8,
        "jns" => 0x9,
        "jp" => 0xa,
        "jnp" => 0xb,
        "jl" => 0xc,
        "jge" => 0xd,
        "jle" => 0xe,
        "jg" => 0xf,
        _ => return None,
    })
}

fn mnemonic_for_jcc(opcode_low: u8) -> &'static str {
    match opcode_low & 0x0f {
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
