use crate::{
    arch::aarch64::{
        format::render_instruction,
        registers::{w, w_or_sp, w_or_zr, x, x_or_sp, x_or_zr},
    },
    bits::{bits, sign_extend},
    error::{DecodeError, EncodeError, TextError},
    form::{FormId, InstructionForm},
    model::{
        Architecture, DecodeStatus, FlowKind, Instruction, InstructionKind, Operand, Register,
    },
};

const RET_WORD: u32 = 0xd65f03c0;
const NOP_WORD: u32 = 0xd503201f;

static FORMS: &[InstructionForm] = &[
    InstructionForm::new(
        FormId::new(Architecture::Aarch64, "nop"),
        "nop",
        InstructionKind::System,
        FlowKind::Fallthrough,
        decode_nop,
        encode_nop,
        parse_nop,
    ),
    InstructionForm::new(
        FormId::new(Architecture::Aarch64, "ret"),
        "ret",
        InstructionKind::Return,
        FlowKind::Return,
        decode_ret,
        encode_ret,
        parse_ret,
    ),
    InstructionForm::new(
        FormId::new(Architecture::Aarch64, "br"),
        "br",
        InstructionKind::Branch,
        FlowKind::IndirectBranch,
        decode_br,
        encode_br,
        parse_br,
    ),
    InstructionForm::new(
        FormId::new(Architecture::Aarch64, "blr"),
        "blr",
        InstructionKind::Call,
        FlowKind::IndirectCall,
        decode_blr,
        encode_blr,
        parse_blr,
    ),
    InstructionForm::new(
        FormId::new(Architecture::Aarch64, "b_imm26"),
        "b",
        InstructionKind::Branch,
        FlowKind::Branch,
        decode_b,
        encode_b,
        parse_b,
    ),
    InstructionForm::new(
        FormId::new(Architecture::Aarch64, "bl_imm26"),
        "bl",
        InstructionKind::Call,
        FlowKind::Call,
        decode_bl,
        encode_bl,
        parse_bl,
    ),
    InstructionForm::new(
        FormId::new(Architecture::Aarch64, "b_cond"),
        "b.cond",
        InstructionKind::Branch,
        FlowKind::ConditionalBranch,
        decode_b_cond,
        encode_b_cond,
        parse_b_cond,
    ),
    InstructionForm::new(
        FormId::new(Architecture::Aarch64, "cbz"),
        "cbz",
        InstructionKind::Compare,
        FlowKind::ConditionalBranch,
        decode_cbz,
        encode_cbz,
        parse_cbz,
    ),
    InstructionForm::new(
        FormId::new(Architecture::Aarch64, "cbnz"),
        "cbnz",
        InstructionKind::Compare,
        FlowKind::ConditionalBranch,
        decode_cbnz,
        encode_cbnz,
        parse_cbnz,
    ),
    InstructionForm::new(
        FormId::new(Architecture::Aarch64, "tbz"),
        "tbz",
        InstructionKind::Compare,
        FlowKind::ConditionalBranch,
        decode_tbz,
        encode_tbz,
        parse_tbz,
    ),
    InstructionForm::new(
        FormId::new(Architecture::Aarch64, "tbnz"),
        "tbnz",
        InstructionKind::Compare,
        FlowKind::ConditionalBranch,
        decode_tbnz,
        encode_tbnz,
        parse_tbnz,
    ),
    InstructionForm::new(
        FormId::new(Architecture::Aarch64, "adr"),
        "adr",
        InstructionKind::Address,
        FlowKind::Fallthrough,
        decode_adr,
        encode_adr,
        parse_adr,
    ),
    InstructionForm::new(
        FormId::new(Architecture::Aarch64, "adrp"),
        "adrp",
        InstructionKind::Address,
        FlowKind::Fallthrough,
        decode_adrp,
        encode_adrp,
        parse_adrp,
    ),
    InstructionForm::new(
        FormId::new(Architecture::Aarch64, "add_imm"),
        "add",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        decode_add_imm,
        encode_add_imm,
        parse_add_imm,
    ),
    InstructionForm::new(
        FormId::new(Architecture::Aarch64, "sub_imm"),
        "sub",
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        decode_sub_imm,
        encode_sub_imm,
        parse_sub_imm,
    ),
    InstructionForm::new(
        FormId::new(Architecture::Aarch64, "cmp_imm"),
        "cmp",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        decode_cmp_imm,
        encode_cmp_imm,
        parse_cmp_imm,
    ),
    InstructionForm::new(
        FormId::new(Architecture::Aarch64, "cmn_imm"),
        "cmn",
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        decode_cmn_imm,
        encode_cmn_imm,
        parse_cmn_imm,
    ),
    InstructionForm::new(
        FormId::new(Architecture::Aarch64, "move_wide"),
        "mov",
        InstructionKind::Move,
        FlowKind::Fallthrough,
        decode_move_wide,
        encode_move_wide,
        parse_move_wide,
    ),
    InstructionForm::new(
        FormId::new(Architecture::Aarch64, "logical_imm"),
        "and",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        decode_logical_imm,
        encode_logical_imm,
        parse_logical_imm,
    ),
    InstructionForm::new(
        FormId::new(Architecture::Aarch64, "bitfield_alias"),
        "lsr",
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        decode_bitfield_alias,
        encode_bitfield_alias,
        parse_bitfield_alias,
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

fn decode_nop(bytes: &[u8], address: u64) -> Result<Option<Instruction>, DecodeError> {
    let word = read_word(bytes)?;
    Ok((word == NOP_WORD).then(|| {
        base(
            word,
            address,
            "nop",
            Vec::new(),
            InstructionKind::System,
            FlowKind::Fallthrough,
            None,
        )
    }))
}

fn decode_ret(bytes: &[u8], address: u64) -> Result<Option<Instruction>, DecodeError> {
    let word = read_word(bytes)?;
    if word & 0xffff_fc1f != 0xd65f_0000 {
        return Ok(None);
    }
    let rn = bits(word, 5, 9);
    let operands = if rn == 30 {
        Vec::new()
    } else {
        vec![Operand::Register(x(rn))]
    };
    Ok(Some(base(
        word,
        address,
        "ret",
        operands,
        InstructionKind::Return,
        FlowKind::Return,
        None,
    )))
}

fn decode_br(bytes: &[u8], address: u64) -> Result<Option<Instruction>, DecodeError> {
    decode_reg_branch(
        bytes,
        address,
        0xd61f_0000,
        "br",
        InstructionKind::Branch,
        FlowKind::IndirectBranch,
    )
}

fn decode_blr(bytes: &[u8], address: u64) -> Result<Option<Instruction>, DecodeError> {
    decode_reg_branch(
        bytes,
        address,
        0xd63f_0000,
        "blr",
        InstructionKind::Call,
        FlowKind::IndirectCall,
    )
}

fn decode_reg_branch(
    bytes: &[u8],
    address: u64,
    value: u32,
    mnemonic: &str,
    kind: InstructionKind,
    flow: FlowKind,
) -> Result<Option<Instruction>, DecodeError> {
    let word = read_word(bytes)?;
    if word & 0xffff_fc1f != value {
        return Ok(None);
    }
    let rn = bits(word, 5, 9);
    Ok(Some(base(
        word,
        address,
        mnemonic,
        vec![Operand::Register(x_or_zr(rn))],
        kind,
        flow,
        None,
    )))
}

fn decode_b(bytes: &[u8], address: u64) -> Result<Option<Instruction>, DecodeError> {
    decode_b_or_bl(bytes, address, false)
}

fn decode_bl(bytes: &[u8], address: u64) -> Result<Option<Instruction>, DecodeError> {
    decode_b_or_bl(bytes, address, true)
}

fn decode_b_or_bl(
    bytes: &[u8],
    address: u64,
    link: bool,
) -> Result<Option<Instruction>, DecodeError> {
    let word = read_word(bytes)?;
    if word & 0x7c00_0000 != 0x1400_0000 {
        return Ok(None);
    }
    if (bits(word, 31, 31) == 1) != link {
        return Ok(None);
    }
    let imm26 = bits(word, 0, 25);
    let offset = sign_extend(imm26 << 2, 28);
    let target = address.wrapping_add_signed(offset);
    Ok(Some(base(
        word,
        address,
        if link { "bl" } else { "b" },
        vec![Operand::AbsoluteAddress(target)],
        if link {
            InstructionKind::Call
        } else {
            InstructionKind::Branch
        },
        if link {
            FlowKind::Call
        } else {
            FlowKind::Branch
        },
        Some(target),
    )))
}

fn decode_b_cond(bytes: &[u8], address: u64) -> Result<Option<Instruction>, DecodeError> {
    let word = read_word(bytes)?;
    if word & 0xff00_0010 != 0x5400_0000 {
        return Ok(None);
    }
    let imm19 = bits(word, 5, 23);
    let offset = sign_extend(imm19 << 2, 21);
    let target = address.wrapping_add_signed(offset);
    let Some(cond_name) = condition_name(bits(word, 0, 3)) else {
        return Ok(None);
    };
    let mnemonic = format!("b.{cond_name}");
    Ok(Some(base(
        word,
        address,
        &mnemonic,
        vec![Operand::AbsoluteAddress(target)],
        InstructionKind::Branch,
        FlowKind::ConditionalBranch,
        Some(target),
    )))
}

fn decode_cbz(bytes: &[u8], address: u64) -> Result<Option<Instruction>, DecodeError> {
    decode_cbz_family(bytes, address, false)
}

fn decode_cbnz(bytes: &[u8], address: u64) -> Result<Option<Instruction>, DecodeError> {
    decode_cbz_family(bytes, address, true)
}

fn decode_cbz_family(
    bytes: &[u8],
    address: u64,
    nonzero: bool,
) -> Result<Option<Instruction>, DecodeError> {
    let word = read_word(bytes)?;
    if word & 0x7e00_0000 != 0x3400_0000 || (bits(word, 24, 24) == 1) != nonzero {
        return Ok(None);
    }
    let is_64 = bits(word, 31, 31) == 1;
    let rt = bits(word, 0, 4);
    let imm19 = bits(word, 5, 23);
    let offset = sign_extend(imm19 << 2, 21);
    let target = address.wrapping_add_signed(offset);
    Ok(Some(base(
        word,
        address,
        if nonzero { "cbnz" } else { "cbz" },
        vec![
            Operand::Register(if is_64 { x(rt) } else { w(rt) }),
            Operand::AbsoluteAddress(target),
        ],
        InstructionKind::Compare,
        FlowKind::ConditionalBranch,
        Some(target),
    )))
}

fn decode_tbz(bytes: &[u8], address: u64) -> Result<Option<Instruction>, DecodeError> {
    decode_tbz_family(bytes, address, false)
}

fn decode_tbnz(bytes: &[u8], address: u64) -> Result<Option<Instruction>, DecodeError> {
    decode_tbz_family(bytes, address, true)
}

fn decode_tbz_family(
    bytes: &[u8],
    address: u64,
    nonzero: bool,
) -> Result<Option<Instruction>, DecodeError> {
    let word = read_word(bytes)?;
    if word & 0x7e00_0000 != 0x3600_0000 || (bits(word, 24, 24) == 1) != nonzero {
        return Ok(None);
    }
    let b5 = bits(word, 31, 31);
    let b40 = bits(word, 19, 23);
    let bit = (b5 << 5) | b40;
    let rt = bits(word, 0, 4);
    let imm14 = bits(word, 5, 18);
    let offset = sign_extend(imm14 << 2, 16);
    let target = address.wrapping_add_signed(offset);
    Ok(Some(base(
        word,
        address,
        if nonzero { "tbnz" } else { "tbz" },
        vec![
            Operand::Register(if b5 == 1 { x(rt) } else { w(rt) }),
            Operand::Immediate(i64::from(bit)),
            Operand::AbsoluteAddress(target),
        ],
        InstructionKind::Compare,
        FlowKind::ConditionalBranch,
        Some(target),
    )))
}

fn decode_adr(bytes: &[u8], address: u64) -> Result<Option<Instruction>, DecodeError> {
    decode_adr_family(bytes, address, false)
}

fn decode_adrp(bytes: &[u8], address: u64) -> Result<Option<Instruction>, DecodeError> {
    decode_adr_family(bytes, address, true)
}

fn decode_adr_family(
    bytes: &[u8],
    address: u64,
    page: bool,
) -> Result<Option<Instruction>, DecodeError> {
    let word = read_word(bytes)?;
    if word & 0x1f00_0000 != 0x1000_0000 || (bits(word, 31, 31) == 1) != page {
        return Ok(None);
    }
    let rd = bits(word, 0, 4);
    let immlo = bits(word, 29, 30);
    let immhi = bits(word, 5, 23);
    let imm = (immhi << 2) | immlo;
    let target = if page {
        let offset = sign_extend(imm, 21) << 12;
        (address & !0xfff).wrapping_add_signed(offset)
    } else {
        let offset = sign_extend(imm, 21);
        address.wrapping_add_signed(offset)
    };
    Ok(Some(base(
        word,
        address,
        if page { "adrp" } else { "adr" },
        vec![Operand::Register(x(rd)), Operand::AbsoluteAddress(target)],
        InstructionKind::Address,
        FlowKind::Fallthrough,
        None,
    )))
}

fn decode_add_imm(bytes: &[u8], address: u64) -> Result<Option<Instruction>, DecodeError> {
    decode_add_sub_imm_family(bytes, address, "add")
}

fn decode_sub_imm(bytes: &[u8], address: u64) -> Result<Option<Instruction>, DecodeError> {
    decode_add_sub_imm_family(bytes, address, "sub")
}

fn decode_cmp_imm(bytes: &[u8], address: u64) -> Result<Option<Instruction>, DecodeError> {
    decode_add_sub_imm_family(bytes, address, "cmp")
}

fn decode_cmn_imm(bytes: &[u8], address: u64) -> Result<Option<Instruction>, DecodeError> {
    decode_add_sub_imm_family(bytes, address, "cmn")
}

fn decode_add_sub_imm_family(
    bytes: &[u8],
    address: u64,
    wanted: &str,
) -> Result<Option<Instruction>, DecodeError> {
    let word = read_word(bytes)?;
    if word & 0x1f00_0000 != 0x1100_0000 {
        return Ok(None);
    }
    let is_64 = bits(word, 31, 31) == 1;
    let sub = bits(word, 30, 30) == 1;
    let set_flags = bits(word, 29, 29) == 1;
    let shift = if bits(word, 22, 22) == 1 { 12 } else { 0 };
    let imm = i64::from(bits(word, 10, 21) << shift);
    let rn = bits(word, 5, 9);
    let rd = bits(word, 0, 4);
    let mnemonic = match (sub, set_flags, rd == 31) {
        (true, true, true) => "cmp",
        (false, true, true) => "cmn",
        (true, false, _) => "sub",
        (false, false, _) => "add",
        _ => return Ok(None),
    };
    if mnemonic != wanted {
        return Ok(None);
    }
    let dst = if is_64 { x_or_sp(rd) } else { w_or_sp(rd) };
    let src = if is_64 { x_or_sp(rn) } else { w_or_sp(rn) };
    let operands = if matches!(mnemonic, "cmp" | "cmn") {
        vec![Operand::Register(src), Operand::Immediate(imm)]
    } else {
        vec![
            Operand::Register(dst),
            Operand::Register(src),
            Operand::Immediate(imm),
        ]
    };
    Ok(Some(base(
        word,
        address,
        mnemonic,
        operands,
        if matches!(mnemonic, "cmp" | "cmn") {
            InstructionKind::Compare
        } else {
            InstructionKind::Arithmetic
        },
        FlowKind::Fallthrough,
        None,
    )))
}

fn decode_move_wide(bytes: &[u8], address: u64) -> Result<Option<Instruction>, DecodeError> {
    let word = read_word(bytes)?;
    if word & 0x1f80_0000 != 0x1280_0000 {
        return Ok(None);
    }
    let is_64 = bits(word, 31, 31) == 1;
    let opc = bits(word, 29, 30);
    let hw = bits(word, 21, 22);
    if !is_64 && hw > 1 {
        return Ok(None);
    }
    let mnemonic = match opc {
        0b00 => "movn",
        0b10 => "mov",
        0b11 => "movk",
        _ => return Ok(None),
    };
    let rd = bits(word, 0, 4);
    let imm = (u64::from(bits(word, 5, 20)) << (hw * 16)) as i64;
    Ok(Some(base(
        word,
        address,
        mnemonic,
        vec![
            Operand::Register(if is_64 { x(rd) } else { w(rd) }),
            Operand::Immediate(imm),
        ],
        InstructionKind::Move,
        FlowKind::Fallthrough,
        None,
    )))
}

fn decode_logical_imm(bytes: &[u8], address: u64) -> Result<Option<Instruction>, DecodeError> {
    let word = read_word(bytes)?;
    if word & 0x1f80_0000 != 0x1200_0000 {
        return Ok(None);
    }
    let is_64 = bits(word, 31, 31) == 1;
    let opc = bits(word, 29, 30);
    let n = bits(word, 22, 22);
    let immr = bits(word, 16, 21);
    let imms = bits(word, 10, 15);
    let rn = bits(word, 5, 9);
    let rd = bits(word, 0, 4);
    let reg_size = if is_64 { 64 } else { 32 };
    let Some(mask) = decode_logical_immediate_mask(n, immr, imms, reg_size) else {
        return Ok(None);
    };

    let dst = if is_64 { x_or_zr(rd) } else { w_or_zr(rd) };
    let src = if is_64 { x_or_zr(rn) } else { w_or_zr(rn) };
    let mnemonic = match (opc, rn == 31) {
        (0b00, _) => "and",
        (0b01, true) => "mov",
        (0b01, false) => "orr",
        (0b10, _) => "eor",
        _ => "ands",
    };
    let operands = if mnemonic == "mov" {
        vec![Operand::Register(dst), Operand::Immediate(mask as i64)]
    } else {
        vec![
            Operand::Register(dst),
            Operand::Register(src),
            Operand::Immediate(mask as i64),
        ]
    };
    Ok(Some(base(
        word,
        address,
        mnemonic,
        operands,
        if mnemonic == "mov" {
            InstructionKind::Move
        } else {
            InstructionKind::Logical
        },
        FlowKind::Fallthrough,
        None,
    )))
}

fn decode_bitfield_alias(bytes: &[u8], address: u64) -> Result<Option<Instruction>, DecodeError> {
    let word = read_word(bytes)?;
    let class = word & 0xffc0_0000;
    if class != 0x5300_0000 && class != 0xd340_0000 && class != 0x9340_0000 {
        return Ok(None);
    }
    let is_64 = bits(word, 31, 31) == 1;
    let signed = bits(word, 29, 30) == 0;
    let immr = bits(word, 16, 21);
    let imms = bits(word, 10, 15);
    let width = if is_64 { 64 } else { 32 };
    let mnemonic_and_shift = if signed && imms == width - 1 {
        Some(("asr", immr))
    } else if !signed && imms == width - 1 {
        Some(("lsr", immr))
    } else if !signed && immr != 0 && imms + 1 == immr {
        Some(("lsl", width - immr))
    } else {
        None
    };
    let Some((mnemonic, shift)) = mnemonic_and_shift else {
        return Ok(None);
    };
    let rn = bits(word, 5, 9);
    let rd = bits(word, 0, 4);
    Ok(Some(base(
        word,
        address,
        mnemonic,
        vec![
            Operand::Register(if is_64 { x_or_zr(rd) } else { w_or_zr(rd) }),
            Operand::Register(if is_64 { x_or_zr(rn) } else { w_or_zr(rn) }),
            Operand::Immediate(i64::from(shift)),
        ],
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        None,
    )))
}

fn encode_move_wide(instruction: &Instruction) -> Option<Vec<u8>> {
    if instruction.flow != FlowKind::Fallthrough {
        return None;
    }
    let [Operand::Register(reg), Operand::Immediate(imm)] = instruction.operands.as_slice() else {
        return None;
    };
    let (is_64, rd) = parse_width_register(&reg.name)?;
    let (imm16, hw) = encode_move_wide_immediate(u64::try_from(*imm).ok()?, is_64)?;
    let opc = match instruction.mnemonic.as_str() {
        "movn" => 0b00,
        "mov" | "movz" => 0b10,
        "movk" => 0b11,
        _ => return None,
    };
    let mut word = 0x1280_0000u32 | (opc << 29) | (hw << 21) | (imm16 << 5) | rd;
    if is_64 {
        word |= 1 << 31;
    }
    Some(word.to_le_bytes().to_vec())
}

fn parse_move_wide(text: &str, address: u64) -> Option<Instruction> {
    let (mnemonic, reg, imm) = parse_register_immediate_for_any_mnemonic(text)?;
    if !matches!(mnemonic, "mov" | "movz" | "movk" | "movn") {
        return None;
    }
    let bytes = encode_move_wide(&Instruction {
        address,
        size: 4,
        bytes: Vec::new(),
        mnemonic: mnemonic.to_string(),
        operands: vec![Operand::Register(reg.clone()), Operand::Immediate(imm)],
        text: String::new(),
        kind: InstructionKind::Move,
        flow: FlowKind::Fallthrough,
        branch_target: None,
        status: DecodeStatus::Complete,
    })?;
    Some(base(
        u32::from_le_bytes(bytes.try_into().ok()?),
        address,
        mnemonic,
        vec![Operand::Register(reg), Operand::Immediate(imm)],
        InstructionKind::Move,
        FlowKind::Fallthrough,
        None,
    ))
}

fn encode_logical_imm(instruction: &Instruction) -> Option<Vec<u8>> {
    if instruction.flow != FlowKind::Fallthrough {
        return None;
    }
    let (opc, rn, rd, is_64, imm, kind) = match instruction.mnemonic.as_str() {
        "mov" => {
            let [Operand::Register(dst), Operand::Immediate(imm)] = instruction.operands.as_slice()
            else {
                return None;
            };
            let (is_64, rd) = parse_width_register(&dst.name)?;
            (0b01, 31, rd, is_64, *imm, InstructionKind::Move)
        }
        "and" | "orr" | "eor" | "ands" => {
            let [Operand::Register(dst), Operand::Register(src), Operand::Immediate(imm)] =
                instruction.operands.as_slice()
            else {
                return None;
            };
            let (is_64, rd) = parse_width_register(&dst.name)?;
            let (src_is_64, rn) = parse_width_register(&src.name)?;
            if src_is_64 != is_64 {
                return None;
            }
            let opc = match instruction.mnemonic.as_str() {
                "and" => 0b00,
                "orr" => 0b01,
                "eor" => 0b10,
                _ => 0b11,
            };
            (opc, rn, rd, is_64, *imm, InstructionKind::Logical)
        }
        _ => return None,
    };
    let mask = if is_64 { imm as u64 } else { imm as u32 as u64 };
    let (n, immr, imms) = encode_logical_immediate_fields(mask, is_64)?;
    let mut word =
        0x1200_0000u32 | (opc << 29) | (n << 22) | (immr << 16) | (imms << 10) | (rn << 5) | rd;
    if is_64 {
        word |= 1 << 31;
    }
    let _ = kind;
    Some(word.to_le_bytes().to_vec())
}

fn parse_logical_imm(text: &str, address: u64) -> Option<Instruction> {
    let text = text.trim();
    let (mnemonic, _) = text.split_once(' ')?;
    let (operands, kind) = if mnemonic == "mov" {
        let (reg, imm) = parse_register_immediate(text, "mov")?;
        (
            vec![Operand::Register(reg), Operand::Immediate(imm)],
            InstructionKind::Move,
        )
    } else {
        (
            parse_two_registers_and_immediate(text, mnemonic)?,
            InstructionKind::Logical,
        )
    };
    let bytes = encode_logical_imm(&Instruction {
        address,
        size: 4,
        bytes: Vec::new(),
        mnemonic: mnemonic.to_string(),
        operands: operands.clone(),
        text: String::new(),
        kind,
        flow: FlowKind::Fallthrough,
        branch_target: None,
        status: DecodeStatus::Complete,
    })?;
    Some(base(
        u32::from_le_bytes(bytes.try_into().ok()?),
        address,
        mnemonic,
        operands,
        kind,
        FlowKind::Fallthrough,
        None,
    ))
}

fn encode_bitfield_alias(instruction: &Instruction) -> Option<Vec<u8>> {
    if instruction.flow != FlowKind::Fallthrough {
        return None;
    }
    let [Operand::Register(dst), Operand::Register(src), Operand::Immediate(shift)] =
        instruction.operands.as_slice()
    else {
        return None;
    };
    let (is_64, rd) = parse_width_register(&dst.name)?;
    let (src_is_64, rn) = parse_width_register(&src.name)?;
    if src_is_64 != is_64 {
        return None;
    }
    let width = if is_64 { 64 } else { 32 };
    let shift = u32::try_from(*shift).ok()?;
    let (base_word, immr, imms) = match instruction.mnemonic.as_str() {
        "lsr" => (
            if is_64 { 0xd340_0000 } else { 0x5300_0000 },
            shift,
            width - 1,
        ),
        "asr" => (
            if is_64 { 0x9340_0000 } else { 0x1300_0000 },
            shift,
            width - 1,
        ),
        "lsl" => {
            if shift == 0 || shift >= width {
                return None;
            }
            let immr = width - shift;
            (
                if is_64 { 0xd340_0000 } else { 0x5300_0000 },
                immr,
                immr - 1,
            )
        }
        _ => return None,
    };
    if immr >= width || imms >= width {
        return None;
    }
    let word = base_word | (immr << 16) | (imms << 10) | (rn << 5) | rd;
    Some(word.to_le_bytes().to_vec())
}

fn parse_bitfield_alias(text: &str, address: u64) -> Option<Instruction> {
    let text = text.trim();
    let (mnemonic, _) = text.split_once(' ')?;
    if !matches!(mnemonic, "lsr" | "lsl" | "asr") {
        return None;
    }
    let operands = parse_two_registers_and_immediate(text, mnemonic)?;
    let bytes = encode_bitfield_alias(&Instruction {
        address,
        size: 4,
        bytes: Vec::new(),
        mnemonic: mnemonic.to_string(),
        operands: operands.clone(),
        text: String::new(),
        kind: InstructionKind::Logical,
        flow: FlowKind::Fallthrough,
        branch_target: None,
        status: DecodeStatus::Complete,
    })?;
    Some(base(
        u32::from_le_bytes(bytes.try_into().ok()?),
        address,
        mnemonic,
        operands,
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        None,
    ))
}

fn encode_nop(instruction: &Instruction) -> Option<Vec<u8>> {
    (instruction.mnemonic == "nop"
        && instruction.operands.is_empty()
        && instruction.flow == FlowKind::Fallthrough)
        .then(|| NOP_WORD.to_le_bytes().to_vec())
}

fn parse_nop(text: &str, address: u64) -> Option<Instruction> {
    (text.trim() == "nop").then(|| {
        base(
            NOP_WORD,
            address,
            "nop",
            Vec::new(),
            InstructionKind::System,
            FlowKind::Fallthrough,
            None,
        )
    })
}

fn encode_ret(instruction: &Instruction) -> Option<Vec<u8>> {
    if instruction.mnemonic != "ret" || instruction.flow != FlowKind::Return {
        return None;
    }
    let rn = match instruction.operands.as_slice() {
        [] => 30,
        [Operand::Register(reg)] => parse_x_branch_register(&reg.name)?,
        _ => return None,
    };
    Some((0xd65f_0000u32 | (rn << 5)).to_le_bytes().to_vec())
}

fn parse_ret(text: &str, address: u64) -> Option<Instruction> {
    let rest = text.trim().strip_prefix("ret")?.trim();
    if rest.is_empty() {
        return Some(base(
            RET_WORD,
            address,
            "ret",
            Vec::new(),
            InstructionKind::Return,
            FlowKind::Return,
            None,
        ));
    }
    let rn = parse_x_branch_register(rest)?;
    let word = 0xd65f_0000u32 | (rn << 5);
    Some(base(
        word,
        address,
        "ret",
        vec![Operand::Register(x(rn))],
        InstructionKind::Return,
        FlowKind::Return,
        None,
    ))
}

fn encode_br(instruction: &Instruction) -> Option<Vec<u8>> {
    encode_reg_branch(instruction, "br", 0xd61f_0000)
}

fn parse_br(text: &str, address: u64) -> Option<Instruction> {
    parse_reg_branch(
        text,
        address,
        "br",
        0xd61f_0000,
        InstructionKind::Branch,
        FlowKind::IndirectBranch,
    )
}

fn encode_blr(instruction: &Instruction) -> Option<Vec<u8>> {
    encode_reg_branch(instruction, "blr", 0xd63f_0000)
}

fn parse_blr(text: &str, address: u64) -> Option<Instruction> {
    parse_reg_branch(
        text,
        address,
        "blr",
        0xd63f_0000,
        InstructionKind::Call,
        FlowKind::IndirectCall,
    )
}

fn encode_reg_branch(instruction: &Instruction, mnemonic: &str, opcode: u32) -> Option<Vec<u8>> {
    if instruction.mnemonic != mnemonic {
        return None;
    }
    let [Operand::Register(reg)] = instruction.operands.as_slice() else {
        return None;
    };
    let rn = parse_x_branch_register(&reg.name)?;
    Some((opcode | (rn << 5)).to_le_bytes().to_vec())
}

fn parse_reg_branch(
    text: &str,
    address: u64,
    mnemonic: &str,
    opcode: u32,
    kind: InstructionKind,
    flow: FlowKind,
) -> Option<Instruction> {
    let reg_text = text.trim().strip_prefix(mnemonic)?.trim();
    let rn = parse_x_branch_register(reg_text)?;
    Some(base(
        opcode | (rn << 5),
        address,
        mnemonic,
        vec![Operand::Register(x_or_zr(rn))],
        kind,
        flow,
        None,
    ))
}

fn encode_b(instruction: &Instruction) -> Option<Vec<u8>> {
    encode_b_or_bl(instruction, "b", false)
}

fn parse_b(text: &str, address: u64) -> Option<Instruction> {
    parse_b_or_bl(text, address, "b", false)
}

fn encode_bl(instruction: &Instruction) -> Option<Vec<u8>> {
    encode_b_or_bl(instruction, "bl", true)
}

fn parse_bl(text: &str, address: u64) -> Option<Instruction> {
    parse_b_or_bl(text, address, "bl", true)
}

fn encode_b_or_bl(instruction: &Instruction, mnemonic: &str, link: bool) -> Option<Vec<u8>> {
    if instruction.mnemonic != mnemonic {
        return None;
    }
    let target = extract_branch_target(instruction)?;
    let delta = i64::try_from(target).ok()? - i64::try_from(instruction.address).ok()?;
    if delta % 4 != 0 {
        return None;
    }
    let imm26 = delta / 4;
    if !(-(1i64 << 25)..(1i64 << 25)).contains(&imm26) {
        return None;
    }
    let word =
        (if link { 0x9400_0000u32 } else { 0x1400_0000u32 }) | ((imm26 as u32) & 0x03ff_ffff);
    Some(word.to_le_bytes().to_vec())
}

fn parse_b_or_bl(text: &str, address: u64, mnemonic: &str, link: bool) -> Option<Instruction> {
    let target = parse_absolute_target(text, mnemonic)?;
    let word = encode_b_or_bl(
        &Instruction {
            address,
            size: 4,
            bytes: Vec::new(),
            mnemonic: mnemonic.to_string(),
            operands: vec![Operand::AbsoluteAddress(target)],
            text: String::new(),
            kind: if link {
                InstructionKind::Call
            } else {
                InstructionKind::Branch
            },
            flow: if link {
                FlowKind::Call
            } else {
                FlowKind::Branch
            },
            branch_target: Some(target),
            status: DecodeStatus::Complete,
        },
        mnemonic,
        link,
    )?;
    Some(base(
        u32::from_le_bytes(word.try_into().ok()?),
        address,
        mnemonic,
        vec![Operand::AbsoluteAddress(target)],
        if link {
            InstructionKind::Call
        } else {
            InstructionKind::Branch
        },
        if link {
            FlowKind::Call
        } else {
            FlowKind::Branch
        },
        Some(target),
    ))
}

fn encode_b_cond(instruction: &Instruction) -> Option<Vec<u8>> {
    let cond_name = instruction.mnemonic.strip_prefix("b.")?;
    let cond = condition_bits(cond_name)?;
    let target = extract_branch_target(instruction)?;
    let delta = i64::try_from(target).ok()? - i64::try_from(instruction.address).ok()?;
    if delta % 4 != 0 {
        return None;
    }
    let imm19 = delta / 4;
    if !(-(1i64 << 18)..(1i64 << 18)).contains(&imm19) {
        return None;
    }
    let word = 0x5400_0000u32 | (((imm19 as u32) & 0x7ffff) << 5) | cond;
    Some(word.to_le_bytes().to_vec())
}

fn parse_b_cond(text: &str, address: u64) -> Option<Instruction> {
    let text = text.trim();
    let (mnemonic, target_text) = text.split_once(' ')?;
    let cond_name = mnemonic.strip_prefix("b.")?;
    let cond = condition_bits(cond_name)?;
    let target = parse_target_text(target_text.trim())?;
    let delta = i64::try_from(target).ok()? - i64::try_from(address).ok()?;
    if delta % 4 != 0 {
        return None;
    }
    let imm19 = delta / 4;
    if !(-(1i64 << 18)..(1i64 << 18)).contains(&imm19) {
        return None;
    }
    let word = 0x5400_0000u32 | (((imm19 as u32) & 0x7ffff) << 5) | cond;
    Some(base(
        word,
        address,
        mnemonic,
        vec![Operand::AbsoluteAddress(target)],
        InstructionKind::Branch,
        FlowKind::ConditionalBranch,
        Some(target),
    ))
}

fn encode_cbz(instruction: &Instruction) -> Option<Vec<u8>> {
    encode_cbz_family(instruction, "cbz", false)
}

fn parse_cbz(text: &str, address: u64) -> Option<Instruction> {
    parse_cbz_family(text, address, "cbz", false)
}

fn encode_cbnz(instruction: &Instruction) -> Option<Vec<u8>> {
    encode_cbz_family(instruction, "cbnz", true)
}

fn parse_cbnz(text: &str, address: u64) -> Option<Instruction> {
    parse_cbz_family(text, address, "cbnz", true)
}

fn encode_cbz_family(instruction: &Instruction, mnemonic: &str, nonzero: bool) -> Option<Vec<u8>> {
    if instruction.mnemonic != mnemonic {
        return None;
    }
    let [Operand::Register(reg), Operand::AbsoluteAddress(target)] =
        instruction.operands.as_slice()
    else {
        return None;
    };
    let (is_64, rt) = parse_width_register(&reg.name)?;
    let delta = i64::try_from(*target).ok()? - i64::try_from(instruction.address).ok()?;
    if delta % 4 != 0 {
        return None;
    }
    let imm19 = delta / 4;
    if !(-(1i64 << 18)..(1i64 << 18)).contains(&imm19) {
        return None;
    }
    let mut word = 0x3400_0000u32 | (((imm19 as u32) & 0x7ffff) << 5) | rt;
    if is_64 {
        word |= 1 << 31;
    }
    if nonzero {
        word |= 1 << 24;
    }
    Some(word.to_le_bytes().to_vec())
}

fn parse_cbz_family(
    text: &str,
    address: u64,
    mnemonic: &str,
    nonzero: bool,
) -> Option<Instruction> {
    let (reg, target) = parse_register_and_target(text, mnemonic)?;
    let (is_64, rt) = parse_width_register(&reg.name)?;
    let delta = i64::try_from(target).ok()? - i64::try_from(address).ok()?;
    if delta % 4 != 0 {
        return None;
    }
    let imm19 = delta / 4;
    if !(-(1i64 << 18)..(1i64 << 18)).contains(&imm19) {
        return None;
    }
    let mut word = 0x3400_0000u32 | (((imm19 as u32) & 0x7ffff) << 5) | rt;
    if is_64 {
        word |= 1 << 31;
    }
    if nonzero {
        word |= 1 << 24;
    }
    Some(base(
        word,
        address,
        mnemonic,
        vec![Operand::Register(reg), Operand::AbsoluteAddress(target)],
        InstructionKind::Compare,
        FlowKind::ConditionalBranch,
        Some(target),
    ))
}

fn encode_tbz(instruction: &Instruction) -> Option<Vec<u8>> {
    encode_tbz_family(instruction, "tbz", false)
}

fn parse_tbz(text: &str, address: u64) -> Option<Instruction> {
    parse_tbz_family(text, address, "tbz", false)
}

fn encode_tbnz(instruction: &Instruction) -> Option<Vec<u8>> {
    encode_tbz_family(instruction, "tbnz", true)
}

fn parse_tbnz(text: &str, address: u64) -> Option<Instruction> {
    parse_tbz_family(text, address, "tbnz", true)
}

fn encode_adr(instruction: &Instruction) -> Option<Vec<u8>> {
    encode_adr_family(instruction, "adr", false)
}

fn parse_adr(text: &str, address: u64) -> Option<Instruction> {
    parse_adr_family(text, address, "adr", false)
}

fn encode_adrp(instruction: &Instruction) -> Option<Vec<u8>> {
    encode_adr_family(instruction, "adrp", true)
}

fn parse_adrp(text: &str, address: u64) -> Option<Instruction> {
    parse_adr_family(text, address, "adrp", true)
}

fn encode_adr_family(instruction: &Instruction, mnemonic: &str, page: bool) -> Option<Vec<u8>> {
    if instruction.mnemonic != mnemonic || instruction.flow != FlowKind::Fallthrough {
        return None;
    }
    let [Operand::Register(reg), Operand::AbsoluteAddress(target)] =
        instruction.operands.as_slice()
    else {
        return None;
    };
    let rd = parse_x_only_register(&reg.name)?;
    let imm = if page {
        if *target & 0xfff != 0 {
            return None;
        }
        let base = instruction.address & !0xfff;
        let delta = i64::try_from(*target).ok()? - i64::try_from(base).ok()?;
        if delta % 4096 != 0 {
            return None;
        }
        delta / 4096
    } else {
        i64::try_from(*target).ok()? - i64::try_from(instruction.address).ok()?
    };
    if !(-(1i64 << 20)..(1i64 << 20)).contains(&imm) {
        return None;
    }
    let imm_u32 = (imm as i32 as u32) & 0x1f_ffff;
    let immlo = imm_u32 & 0x3;
    let immhi = (imm_u32 >> 2) & 0x7ffff;
    let base = if page { 0x9000_0000u32 } else { 0x1000_0000u32 };
    let word = base | (immlo << 29) | (immhi << 5) | rd;
    Some(word.to_le_bytes().to_vec())
}

fn parse_adr_family(text: &str, address: u64, mnemonic: &str, page: bool) -> Option<Instruction> {
    let (reg, target) = parse_register_and_target(text, mnemonic)?;
    let bytes = encode_adr_family(
        &Instruction {
            address,
            size: 4,
            bytes: Vec::new(),
            mnemonic: mnemonic.to_string(),
            operands: vec![
                Operand::Register(reg.clone()),
                Operand::AbsoluteAddress(target),
            ],
            text: String::new(),
            kind: InstructionKind::Address,
            flow: FlowKind::Fallthrough,
            branch_target: None,
            status: DecodeStatus::Complete,
        },
        mnemonic,
        page,
    )?;
    Some(base(
        u32::from_le_bytes(bytes.try_into().ok()?),
        address,
        mnemonic,
        vec![Operand::Register(reg), Operand::AbsoluteAddress(target)],
        InstructionKind::Address,
        FlowKind::Fallthrough,
        None,
    ))
}

fn encode_add_imm(instruction: &Instruction) -> Option<Vec<u8>> {
    encode_add_sub_imm_instruction(instruction, "add")
}

fn parse_add_imm(text: &str, address: u64) -> Option<Instruction> {
    parse_add_sub_imm_instruction(text, address, "add")
}

fn encode_sub_imm(instruction: &Instruction) -> Option<Vec<u8>> {
    encode_add_sub_imm_instruction(instruction, "sub")
}

fn parse_sub_imm(text: &str, address: u64) -> Option<Instruction> {
    parse_add_sub_imm_instruction(text, address, "sub")
}

fn encode_cmp_imm(instruction: &Instruction) -> Option<Vec<u8>> {
    encode_add_sub_imm_instruction(instruction, "cmp")
}

fn parse_cmp_imm(text: &str, address: u64) -> Option<Instruction> {
    parse_add_sub_imm_instruction(text, address, "cmp")
}

fn encode_cmn_imm(instruction: &Instruction) -> Option<Vec<u8>> {
    encode_add_sub_imm_instruction(instruction, "cmn")
}

fn parse_cmn_imm(text: &str, address: u64) -> Option<Instruction> {
    parse_add_sub_imm_instruction(text, address, "cmn")
}

fn encode_add_sub_imm_instruction(instruction: &Instruction, mnemonic: &str) -> Option<Vec<u8>> {
    if instruction.mnemonic != mnemonic || instruction.flow != FlowKind::Fallthrough {
        return None;
    }
    let (is_64, rn, rd, imm) = match mnemonic {
        "cmp" | "cmn" => {
            let [Operand::Register(src), Operand::Immediate(imm)] = instruction.operands.as_slice()
            else {
                return None;
            };
            let (is_64, rn) = parse_sp_capable_register(&src.name)?;
            (is_64, rn, 31, *imm)
        }
        "add" | "sub" => {
            let [Operand::Register(dst), Operand::Register(src), Operand::Immediate(imm)] =
                instruction.operands.as_slice()
            else {
                return None;
            };
            let (is_64, rd) = parse_sp_capable_register(&dst.name)?;
            let (src_is_64, rn) = parse_sp_capable_register(&src.name)?;
            if src_is_64 != is_64 {
                return None;
            }
            (is_64, rn, rd, *imm)
        }
        _ => return None,
    };
    let (imm12, shift_flag) = encode_add_sub_imm_value(imm)?;
    let (sub, set_flags) = match mnemonic {
        "add" => (false, false),
        "sub" => (true, false),
        "cmp" => (true, true),
        "cmn" => (false, true),
        _ => return None,
    };
    let mut word = 0x1100_0000u32 | (imm12 << 10) | (rn << 5) | rd;
    if is_64 {
        word |= 1 << 31;
    }
    if sub {
        word |= 1 << 30;
    }
    if set_flags {
        word |= 1 << 29;
    }
    if shift_flag {
        word |= 1 << 22;
    }
    Some(word.to_le_bytes().to_vec())
}

fn parse_add_sub_imm_instruction(text: &str, address: u64, mnemonic: &str) -> Option<Instruction> {
    let operands = parse_add_sub_imm_operands(text, mnemonic)?;
    let kind = if matches!(mnemonic, "cmp" | "cmn") {
        InstructionKind::Compare
    } else {
        InstructionKind::Arithmetic
    };
    let bytes = encode_add_sub_imm_instruction(
        &Instruction {
            address,
            size: 4,
            bytes: Vec::new(),
            mnemonic: mnemonic.to_string(),
            operands: operands.clone(),
            text: String::new(),
            kind,
            flow: FlowKind::Fallthrough,
            branch_target: None,
            status: DecodeStatus::Complete,
        },
        mnemonic,
    )?;
    Some(base(
        u32::from_le_bytes(bytes.try_into().ok()?),
        address,
        mnemonic,
        operands,
        kind,
        FlowKind::Fallthrough,
        None,
    ))
}

fn encode_tbz_family(instruction: &Instruction, mnemonic: &str, nonzero: bool) -> Option<Vec<u8>> {
    if instruction.mnemonic != mnemonic {
        return None;
    }
    let [Operand::Register(reg), Operand::Immediate(bit), Operand::AbsoluteAddress(target)] =
        instruction.operands.as_slice()
    else {
        return None;
    };
    let (is_64, rt) = parse_width_register(&reg.name)?;
    let bit = u32::try_from(*bit).ok()?;
    if bit > 63 || (!is_64 && bit > 31) {
        return None;
    }
    let delta = i64::try_from(*target).ok()? - i64::try_from(instruction.address).ok()?;
    if delta % 4 != 0 {
        return None;
    }
    let imm14 = delta / 4;
    if !(-(1i64 << 13)..(1i64 << 13)).contains(&imm14) {
        return None;
    }
    let mut word = 0x3600_0000u32 | (((imm14 as u32) & 0x3fff) << 5) | rt | ((bit & 0x1f) << 19);
    if is_64 {
        word |= 1 << 31;
    }
    if nonzero {
        word |= 1 << 24;
    }
    Some(word.to_le_bytes().to_vec())
}

fn parse_tbz_family(
    text: &str,
    address: u64,
    mnemonic: &str,
    nonzero: bool,
) -> Option<Instruction> {
    let (reg, bit, target) = parse_register_bit_and_target(text, mnemonic)?;
    let (is_64, rt) = parse_width_register(&reg.name)?;
    let delta = i64::try_from(target).ok()? - i64::try_from(address).ok()?;
    if delta % 4 != 0 {
        return None;
    }
    let imm14 = delta / 4;
    if !(-(1i64 << 13)..(1i64 << 13)).contains(&imm14) {
        return None;
    }
    let bit_u32 = u32::try_from(bit).ok()?;
    if bit_u32 > 63 || (!is_64 && bit_u32 > 31) {
        return None;
    }
    let mut word =
        0x3600_0000u32 | (((imm14 as u32) & 0x3fff) << 5) | rt | ((bit_u32 & 0x1f) << 19);
    if is_64 {
        word |= 1 << 31;
    }
    if nonzero {
        word |= 1 << 24;
    }
    Some(base(
        word,
        address,
        mnemonic,
        vec![
            Operand::Register(reg),
            Operand::Immediate(i64::from(bit_u32)),
            Operand::AbsoluteAddress(target),
        ],
        InstructionKind::Compare,
        FlowKind::ConditionalBranch,
        Some(target),
    ))
}

fn read_word(bytes: &[u8]) -> Result<u32, DecodeError> {
    let word = bytes.get(..4).ok_or(DecodeError::TruncatedInstruction {
        expected: 4,
        actual: bytes.len(),
    })?;
    Ok(u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
}

fn base(
    word: u32,
    address: u64,
    mnemonic: &str,
    operands: Vec<Operand>,
    kind: InstructionKind,
    flow: FlowKind,
    branch_target: Option<u64>,
) -> Instruction {
    Instruction {
        address,
        size: 4,
        bytes: word.to_le_bytes().to_vec(),
        mnemonic: mnemonic.to_string(),
        text: render_instruction(mnemonic, &operands),
        operands,
        kind,
        flow,
        branch_target,
        status: DecodeStatus::Complete,
    }
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

fn parse_absolute_target(text: &str, mnemonic: &str) -> Option<u64> {
    let rest = text.trim().strip_prefix(mnemonic)?.trim();
    parse_target_text(rest)
}

fn parse_target_text(text: &str) -> Option<u64> {
    u64::from_str_radix(text.strip_prefix("0x")?.trim(), 16).ok()
}

fn parse_register_and_target(text: &str, mnemonic: &str) -> Option<(Register, u64)> {
    let rest = text.trim().strip_prefix(mnemonic)?.trim();
    let (reg_text, target_text) = rest.split_once(',')?;
    Some((
        parse_width_register_operand(reg_text.trim())?,
        parse_target_text(target_text.trim())?,
    ))
}

fn parse_register_bit_and_target(text: &str, mnemonic: &str) -> Option<(Register, i64, u64)> {
    let rest = text.trim().strip_prefix(mnemonic)?.trim();
    let mut parts = rest.split(',');
    let reg = parse_width_register_operand(parts.next()?.trim())?;
    let bit_text = parts.next()?.trim();
    let target_text = parts.next()?.trim();
    if parts.next().is_some() {
        return None;
    }
    let bit = i64::from_str_radix(bit_text.strip_prefix("#0x")?, 16).ok()?;
    let target = parse_target_text(target_text)?;
    Some((reg, bit, target))
}

fn parse_x_branch_register(name: &str) -> Option<u32> {
    match name {
        "lr" => Some(30),
        "xzr" => Some(31),
        _ => name.strip_prefix('x')?.parse().ok(),
    }
}

fn parse_width_register(name: &str) -> Option<(bool, u32)> {
    match name {
        "lr" => return Some((true, 30)),
        "xzr" => return Some((true, 31)),
        "wzr" => return Some((false, 31)),
        _ => {}
    }
    if let Some(index) = name.strip_prefix('x') {
        return Some((true, index.parse().ok()?));
    }
    if let Some(index) = name.strip_prefix('w') {
        return Some((false, index.parse().ok()?));
    }
    None
}

fn parse_x_only_register(name: &str) -> Option<u32> {
    match name {
        "lr" => Some(30),
        _ => name.strip_prefix('x')?.parse().ok(),
    }
}

fn parse_sp_capable_register(name: &str) -> Option<(bool, u32)> {
    match name {
        "sp" => Some((true, 31)),
        "wsp" => Some((false, 31)),
        _ => parse_width_register(name),
    }
}

fn parse_aarch64_immediate(text: &str) -> Option<i64> {
    let text = text.trim();
    if let Some(hex) = text.strip_prefix("#-0x") {
        return Some(-(i64::from_str_radix(hex, 16).ok()?));
    }
    if let Some(hex) = text.strip_prefix("#0x") {
        return i64::from_str_radix(hex, 16).ok();
    }
    None
}

fn parse_register_immediate(text: &str, mnemonic: &str) -> Option<(Register, i64)> {
    let rest = text.trim().strip_prefix(mnemonic)?.trim();
    let (reg_text, imm_text) = rest.split_once(',')?;
    Some((
        parse_width_register_operand(reg_text.trim())?,
        parse_aarch64_immediate(imm_text.trim())?,
    ))
}

fn parse_register_immediate_for_any_mnemonic(text: &str) -> Option<(&str, Register, i64)> {
    let (mnemonic, _) = text.trim().split_once(' ')?;
    let (reg, imm) = parse_register_immediate(text, mnemonic)?;
    Some((mnemonic, reg, imm))
}

fn parse_two_registers_and_immediate(text: &str, mnemonic: &str) -> Option<Vec<Operand>> {
    let rest = text.trim().strip_prefix(mnemonic)?.trim();
    let parts = rest.split(',').map(str::trim).collect::<Vec<_>>();
    if parts.len() != 3 {
        return None;
    }
    Some(vec![
        Operand::Register(parse_width_register_operand(parts[0])?),
        Operand::Register(parse_width_register_operand(parts[1])?),
        Operand::Immediate(parse_aarch64_immediate(parts[2])?),
    ])
}

fn encode_move_wide_immediate(value: u64, is_64: bool) -> Option<(u32, u32)> {
    let max_hw = if is_64 { 3 } else { 1 };
    for hw in 0..=max_hw {
        let shift = hw * 16;
        let imm16 = value >> shift;
        if imm16 <= 0xffff && value == (imm16 << shift) {
            return Some((imm16 as u32, hw));
        }
    }
    None
}

fn encode_logical_immediate_fields(mask: u64, is_64: bool) -> Option<(u32, u32, u32)> {
    let reg_size = if is_64 { 64 } else { 32 };
    let wanted = if is_64 { mask } else { mask & 0xffff_ffff };
    for n in 0..=1 {
        for immr in 0..64 {
            for imms in 0..64 {
                if decode_logical_immediate_mask(n, immr, imms, reg_size) == Some(wanted) {
                    return Some((n, immr, imms));
                }
            }
        }
    }
    None
}

fn decode_logical_immediate_mask(n: u32, immr: u32, imms: u32, reg_size: u32) -> Option<u64> {
    let selector = (n << 6) | ((!imms) & 0x3f);
    if selector == 0 {
        return None;
    }
    let len = 31 - selector.leading_zeros();
    if len < 1 || (reg_size == 32 && len > 5) {
        return None;
    }
    let levels = (1u32 << len) - 1;
    let s = imms & levels;
    let r = immr & levels;
    if s == levels {
        return None;
    }

    let element_size = 1u32 << len;
    let ones = low_bits_mask(s + 1);
    let element_mask = low_bits_mask(element_size);
    let rotated = rotate_right_with_width(ones, r, element_size) & element_mask;
    let mut out = 0u64;
    let mut shift = 0;
    while shift < reg_size {
        out |= rotated << shift;
        shift += element_size;
    }
    Some(out)
}

fn low_bits_mask(width: u32) -> u64 {
    if width == 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    }
}

fn rotate_right_with_width(value: u64, rotate: u32, width: u32) -> u64 {
    let rotate = rotate % width;
    if rotate == 0 {
        value
    } else {
        (value >> rotate) | (value << (width - rotate))
    }
}

fn encode_add_sub_imm_value(value: i64) -> Option<(u32, bool)> {
    if value < 0 {
        return None;
    }
    let value = u32::try_from(value).ok()?;
    if value <= 0xfff {
        Some((value, false))
    } else if value & 0xfff == 0 && (value >> 12) <= 0xfff {
        Some((value >> 12, true))
    } else {
        None
    }
}

fn parse_add_sub_imm_operands(text: &str, mnemonic: &str) -> Option<Vec<Operand>> {
    let rest = text.trim().strip_prefix(mnemonic)?.trim();
    let parts = rest.split(',').map(str::trim).collect::<Vec<_>>();
    match mnemonic {
        "cmp" | "cmn" => {
            if parts.len() != 2 {
                return None;
            }
            Some(vec![
                Operand::Register(parse_sp_capable_register_operand(parts[0])?),
                Operand::Immediate(parse_aarch64_immediate(parts[1])?),
            ])
        }
        "add" | "sub" => {
            if parts.len() != 3 {
                return None;
            }
            Some(vec![
                Operand::Register(parse_sp_capable_register_operand(parts[0])?),
                Operand::Register(parse_sp_capable_register_operand(parts[1])?),
                Operand::Immediate(parse_aarch64_immediate(parts[2])?),
            ])
        }
        _ => None,
    }
}

fn parse_sp_capable_register_operand(name: &str) -> Option<Register> {
    match name {
        "sp" => Some(x_or_sp(31)),
        "wsp" => Some(w_or_sp(31)),
        _ => parse_width_register_operand(name),
    }
}

fn parse_width_register_operand(name: &str) -> Option<Register> {
    let (is_64, index) = parse_width_register(name)?;
    Some(if is_64 { x(index) } else { w(index) })
}

fn condition_name(cond: u32) -> Option<&'static str> {
    Some(match cond {
        0x0 => "eq",
        0x1 => "ne",
        0x2 => "cs",
        0x3 => "cc",
        0x4 => "mi",
        0x5 => "pl",
        0x6 => "vs",
        0x7 => "vc",
        0x8 => "hi",
        0x9 => "ls",
        0xa => "ge",
        0xb => "lt",
        0xc => "gt",
        0xd => "le",
        0xe => "al",
        0xf => "nv",
        _ => return None,
    })
}

fn condition_bits(name: &str) -> Option<u32> {
    Some(match name {
        "eq" => 0x0,
        "ne" => 0x1,
        "cs" => 0x2,
        "cc" => 0x3,
        "mi" => 0x4,
        "pl" => 0x5,
        "vs" => 0x6,
        "vc" => 0x7,
        "hi" => 0x8,
        "ls" => 0x9,
        "ge" => 0xa,
        "lt" => 0xb,
        "gt" => 0xc,
        "le" => 0xd,
        "al" => 0xe,
        "nv" => 0xf,
        _ => return None,
    })
}
