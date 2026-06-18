use crate::{
    arch::aarch64::{
        format::render_instruction,
        registers::{x, x_or_zr},
    },
    bits::{bits, sign_extend},
    model::{DecodeStatus, FlowKind, Instruction, InstructionKind, Operand},
};

struct Pattern {
    mask: u32,
    value: u32,
    decode: fn(u32, u64) -> Instruction,
}

const PATTERNS: &[Pattern] = &[
    Pattern {
        mask: 0xffff_ffff,
        value: 0xd503_201f,
        decode: decode_nop,
    },
    Pattern {
        mask: 0xffff_fc1f,
        value: 0xd65f_0000,
        decode: decode_ret,
    },
    Pattern {
        mask: 0xffff_fc1f,
        value: 0xd61f_0000,
        decode: decode_br,
    },
    Pattern {
        mask: 0xffff_fc1f,
        value: 0xd63f_0000,
        decode: decode_blr,
    },
    Pattern {
        mask: 0xff00_0010,
        value: 0x5400_0000,
        decode: decode_b_cond,
    },
    Pattern {
        mask: 0x7e00_0000,
        value: 0x3400_0000,
        decode: decode_cbz_cbnz,
    },
    Pattern {
        mask: 0x7e00_0000,
        value: 0x3600_0000,
        decode: decode_tbz_tbnz,
    },
    Pattern {
        mask: 0x1f00_0000,
        value: 0x1000_0000,
        decode: decode_adr_adrp,
    },
    Pattern {
        mask: 0x1f00_0000,
        value: 0x1100_0000,
        decode: decode_add_sub_imm,
    },
    Pattern {
        mask: 0x1f00_0000,
        value: 0x0b00_0000,
        decode: decode_add_sub_shifted_register,
    },
    Pattern {
        mask: 0x1f80_0000,
        value: 0x1280_0000,
        decode: decode_move_wide,
    },
    Pattern {
        mask: 0xffc0_0000,
        value: 0x5300_0000,
        decode: decode_bitfield_alias,
    },
    Pattern {
        mask: 0xffc0_0000,
        value: 0xd340_0000,
        decode: decode_bitfield_alias,
    },
    Pattern {
        mask: 0xffc0_0000,
        value: 0x9340_0000,
        decode: decode_bitfield_alias,
    },
    Pattern {
        mask: 0x1f00_0000,
        value: 0x0a00_0000,
        decode: decode_logical_shifted_register,
    },
    Pattern {
        mask: 0x1f80_0000,
        value: 0x1200_0000,
        decode: decode_logical_immediate,
    },
    Pattern {
        mask: 0x7fe0_fc00,
        value: 0x1ac0_2400,
        decode: decode_lsr_register,
    },
    Pattern {
        mask: 0x1fe0_0000,
        value: 0x1a80_0000,
        decode: decode_conditional_select,
    },
    Pattern {
        mask: 0xffe0_fc00,
        value: 0x6f00_e400,
        decode: decode_movi_zero_2d,
    },
    Pattern {
        mask: 0x7b80_0000,
        value: 0x2880_0000,
        decode: decode_load_store_pair,
    },
    Pattern {
        mask: 0x7b80_0000,
        value: 0x2900_0000,
        decode: decode_load_store_pair,
    },
    Pattern {
        mask: 0x7b80_0000,
        value: 0x2980_0000,
        decode: decode_load_store_pair,
    },
    Pattern {
        mask: 0x3b00_0000,
        value: 0x3900_0000,
        decode: decode_load_store_unsigned,
    },
    Pattern {
        mask: 0x3b20_0c00,
        value: 0x3820_0800,
        decode: decode_load_store_register_offset,
    },
    Pattern {
        mask: 0x3b20_0c00,
        value: 0x3800_0000,
        decode: decode_load_store_unscaled,
    },
    Pattern {
        mask: 0x3b20_0400,
        value: 0x3800_0400,
        decode: decode_load_store_unscaled,
    },
    Pattern {
        mask: 0xffe0_001f,
        value: 0xd420_0000,
        decode: decode_brk,
    },
    Pattern {
        mask: 0x7c00_0000,
        value: 0x1400_0000,
        decode: decode_b_bl,
    },
];

pub fn decode_word(word: u32, address: u64) -> Instruction {
    for pattern in PATTERNS {
        if word & pattern.mask == pattern.value {
            return (pattern.decode)(word, address);
        }
    }
    unknown(word, address)
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

fn decode_ret(word: u32, address: u64) -> Instruction {
    let rn = bits(word, 5, 9);
    let operands = if rn == 30 {
        Vec::new()
    } else {
        vec![Operand::Register(x(rn))]
    };
    base(
        word,
        address,
        "ret",
        operands,
        InstructionKind::Return,
        FlowKind::Return,
        None,
    )
}

fn decode_br(word: u32, address: u64) -> Instruction {
    let rn = bits(word, 5, 9);
    base(
        word,
        address,
        "br",
        vec![Operand::Register(x_or_zr(rn))],
        InstructionKind::Branch,
        FlowKind::IndirectBranch,
        None,
    )
}

fn decode_blr(word: u32, address: u64) -> Instruction {
    let rn = bits(word, 5, 9);
    base(
        word,
        address,
        "blr",
        vec![Operand::Register(x_or_zr(rn))],
        InstructionKind::Call,
        FlowKind::IndirectCall,
        None,
    )
}

fn decode_b_bl(word: u32, address: u64) -> Instruction {
    let link = bits(word, 31, 31) == 1;
    let imm26 = bits(word, 0, 25);
    let offset = sign_extend(imm26 << 2, 28);
    let target = address.wrapping_add_signed(offset);
    base(
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
    )
}

fn condition_name(cond: u32) -> &'static str {
    match cond {
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
        _ => "nv",
    }
}

fn decode_b_cond(word: u32, address: u64) -> Instruction {
    let imm19 = bits(word, 5, 23);
    let offset = sign_extend(imm19 << 2, 21);
    let target = address.wrapping_add_signed(offset);
    let mnemonic = format!("b.{}", condition_name(bits(word, 0, 3)));
    base(
        word,
        address,
        &mnemonic,
        vec![Operand::AbsoluteAddress(target)],
        InstructionKind::Branch,
        FlowKind::ConditionalBranch,
        Some(target),
    )
}

fn decode_cbz_cbnz(word: u32, address: u64) -> Instruction {
    let is_64 = bits(word, 31, 31) == 1;
    let nonzero = bits(word, 24, 24) == 1;
    let rt = bits(word, 0, 4);
    let imm19 = bits(word, 5, 23);
    let offset = sign_extend(imm19 << 2, 21);
    let target = address.wrapping_add_signed(offset);
    let reg = if is_64 {
        crate::arch::aarch64::registers::x(rt)
    } else {
        crate::arch::aarch64::registers::w(rt)
    };
    base(
        word,
        address,
        if nonzero { "cbnz" } else { "cbz" },
        vec![Operand::Register(reg), Operand::AbsoluteAddress(target)],
        InstructionKind::Compare,
        FlowKind::ConditionalBranch,
        Some(target),
    )
}

fn decode_tbz_tbnz(word: u32, address: u64) -> Instruction {
    let nonzero = bits(word, 24, 24) == 1;
    let b5 = bits(word, 31, 31);
    let b40 = bits(word, 19, 23);
    let bit = (b5 << 5) | b40;
    let rt = bits(word, 0, 4);
    let imm14 = bits(word, 5, 18);
    let offset = sign_extend(imm14 << 2, 16);
    let target = address.wrapping_add_signed(offset);
    let reg = if b5 == 1 {
        crate::arch::aarch64::registers::x(rt)
    } else {
        crate::arch::aarch64::registers::w(rt)
    };
    base(
        word,
        address,
        if nonzero { "tbnz" } else { "tbz" },
        vec![
            Operand::Register(reg),
            Operand::Immediate(i64::from(bit)),
            Operand::AbsoluteAddress(target),
        ],
        InstructionKind::Compare,
        FlowKind::ConditionalBranch,
        Some(target),
    )
}

fn decode_adr_adrp(word: u32, address: u64) -> Instruction {
    let page = bits(word, 31, 31) == 1;
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
    base(
        word,
        address,
        if page { "adrp" } else { "adr" },
        vec![Operand::Register(x(rd)), Operand::AbsoluteAddress(target)],
        InstructionKind::Address,
        FlowKind::Fallthrough,
        None,
    )
}

fn decode_nop(word: u32, address: u64) -> Instruction {
    base(
        word,
        address,
        "nop",
        Vec::new(),
        InstructionKind::System,
        FlowKind::Fallthrough,
        None,
    )
}

fn decode_add_sub_imm(word: u32, address: u64) -> Instruction {
    let is_64 = bits(word, 31, 31) == 1;
    let sub = bits(word, 30, 30) == 1;
    let set_flags = bits(word, 29, 29) == 1;
    let shift = if bits(word, 22, 22) == 1 { 12 } else { 0 };
    let imm = i64::from(bits(word, 10, 21) << shift);
    let rn = bits(word, 5, 9);
    let rd = bits(word, 0, 4);
    let dst = if is_64 {
        crate::arch::aarch64::registers::x_or_sp(rd)
    } else {
        crate::arch::aarch64::registers::w_or_sp(rd)
    };
    let src = if is_64 {
        crate::arch::aarch64::registers::x_or_sp(rn)
    } else {
        crate::arch::aarch64::registers::w_or_sp(rn)
    };
    let mnemonic = match (sub, set_flags, rd == 31) {
        (true, true, true) => "cmp",
        (false, true, true) => "cmn",
        (true, true, false) => "subs",
        (false, true, false) => "adds",
        (true, false, _) => "sub",
        (false, false, _) => "add",
    };
    let operands = if matches!(mnemonic, "cmp" | "cmn") {
        vec![Operand::Register(src), Operand::Immediate(imm)]
    } else {
        vec![
            Operand::Register(dst),
            Operand::Register(src),
            Operand::Immediate(imm),
        ]
    };
    base(
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
    )
}

fn decode_add_sub_shifted_register(word: u32, address: u64) -> Instruction {
    let is_64 = bits(word, 31, 31) == 1;
    let sub = bits(word, 30, 30) == 1;
    let set_flags = bits(word, 29, 29) == 1;
    let shift = bits(word, 22, 23);
    let imm6 = bits(word, 10, 15);
    if shift != 0 || imm6 != 0 {
        return unknown(word, address);
    }

    let rm = bits(word, 16, 20);
    let rn = bits(word, 5, 9);
    let rd = bits(word, 0, 4);
    let dst = if is_64 {
        crate::arch::aarch64::registers::x_or_zr(rd)
    } else {
        crate::arch::aarch64::registers::w_or_zr(rd)
    };
    let src1 = if is_64 {
        crate::arch::aarch64::registers::x_or_zr(rn)
    } else {
        crate::arch::aarch64::registers::w_or_zr(rn)
    };
    let src2 = if is_64 {
        crate::arch::aarch64::registers::x_or_zr(rm)
    } else {
        crate::arch::aarch64::registers::w_or_zr(rm)
    };
    let mnemonic = match (sub, set_flags, rd == 31) {
        (true, true, true) => "cmp",
        (false, true, true) => "cmn",
        (true, true, false) => "subs",
        (false, true, false) => "adds",
        (true, false, _) => "sub",
        (false, false, _) => "add",
    };
    let operands = if matches!(mnemonic, "cmp" | "cmn") {
        vec![Operand::Register(src1), Operand::Register(src2)]
    } else {
        vec![
            Operand::Register(dst),
            Operand::Register(src1),
            Operand::Register(src2),
        ]
    };
    base(
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
    )
}

fn decode_move_wide(word: u32, address: u64) -> Instruction {
    let is_64 = bits(word, 31, 31) == 1;
    let opc = bits(word, 29, 30);
    let hw = bits(word, 21, 22);
    let imm = (u64::from(bits(word, 5, 20)) << (hw * 16)) as i64;
    let rd = bits(word, 0, 4);
    let reg = if is_64 {
        crate::arch::aarch64::registers::x(rd)
    } else {
        crate::arch::aarch64::registers::w(rd)
    };
    let mnemonic = match opc {
        0b00 => "movn",
        0b10 => "mov",
        0b11 => "movk",
        _ => "movz",
    };
    base(
        word,
        address,
        mnemonic,
        vec![Operand::Register(reg), Operand::Immediate(imm)],
        InstructionKind::Move,
        FlowKind::Fallthrough,
        None,
    )
}

fn decode_bitfield_alias(word: u32, address: u64) -> Instruction {
    let is_64 = bits(word, 31, 31) == 1;
    let signed = bits(word, 29, 30) == 0;
    let immr = bits(word, 16, 21);
    let imms = bits(word, 10, 15);
    let width = if is_64 { 64 } else { 32 };
    let mnemonic_and_shift = if signed && imms == width - 1 {
        Some(("asr", immr))
    } else if !signed && imms == width - 1 {
        Some(("lsr", immr))
    } else if !signed && imms + 1 == immr {
        Some(("lsl", width - immr))
    } else {
        None
    };
    let Some((mnemonic, shift)) = mnemonic_and_shift else {
        return unknown(word, address);
    };

    let rn = bits(word, 5, 9);
    let rd = bits(word, 0, 4);
    let dst = if is_64 {
        crate::arch::aarch64::registers::x_or_zr(rd)
    } else {
        crate::arch::aarch64::registers::w_or_zr(rd)
    };
    let src = if is_64 {
        crate::arch::aarch64::registers::x_or_zr(rn)
    } else {
        crate::arch::aarch64::registers::w_or_zr(rn)
    };
    base(
        word,
        address,
        mnemonic,
        vec![
            Operand::Register(dst),
            Operand::Register(src),
            Operand::Immediate(i64::from(shift)),
        ],
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        None,
    )
}

fn invert_condition(cond: u32) -> u32 {
    if cond < 0xe {
        cond ^ 1
    } else {
        cond
    }
}

fn conditional_select_condition_name(cond: u32) -> &'static str {
    match cond {
        0x2 => "hs",
        0x3 => "lo",
        _ => condition_name(cond),
    }
}

fn decode_conditional_select(word: u32, address: u64) -> Instruction {
    let is_64 = bits(word, 31, 31) == 1;
    let o2 = bits(word, 10, 10);
    let rm = bits(word, 16, 20);
    let cond = bits(word, 12, 15);
    let rn = bits(word, 5, 9);
    let rd = bits(word, 0, 4);

    let dst = if is_64 {
        crate::arch::aarch64::registers::x_or_zr(rd)
    } else {
        crate::arch::aarch64::registers::w_or_zr(rd)
    };
    let src1 = if is_64 {
        crate::arch::aarch64::registers::x_or_zr(rn)
    } else {
        crate::arch::aarch64::registers::w_or_zr(rn)
    };
    let src2 = if is_64 {
        crate::arch::aarch64::registers::x_or_zr(rm)
    } else {
        crate::arch::aarch64::registers::w_or_zr(rm)
    };

    let (mnemonic, operands) = if o2 == 1 && rn == 31 && rm == 31 {
        (
            "cset",
            vec![
                Operand::Register(dst),
                Operand::Condition(
                    conditional_select_condition_name(invert_condition(cond)).to_string(),
                ),
            ],
        )
    } else if o2 == 0 {
        (
            "csel",
            vec![
                Operand::Register(dst),
                Operand::Register(src1),
                Operand::Register(src2),
                Operand::Condition(conditional_select_condition_name(cond).to_string()),
            ],
        )
    } else {
        return unknown(word, address);
    };

    base(
        word,
        address,
        mnemonic,
        operands,
        InstructionKind::Move,
        FlowKind::Fallthrough,
        None,
    )
}

fn decode_movi_zero_2d(word: u32, address: u64) -> Instruction {
    let rd = bits(word, 0, 4);
    base(
        word,
        address,
        "movi",
        vec![
            Operand::Register(crate::arch::aarch64::registers::v_lane(rd, "2d")),
            Operand::Immediate(0),
        ],
        InstructionKind::Move,
        FlowKind::Fallthrough,
        None,
    )
}

fn decode_logical_shifted_register(word: u32, address: u64) -> Instruction {
    let is_64 = bits(word, 31, 31) == 1;
    let opc = bits(word, 29, 30);
    let rn = bits(word, 5, 9);
    let rm = bits(word, 16, 20);
    let rd = bits(word, 0, 4);
    let dst = if is_64 {
        crate::arch::aarch64::registers::x_or_zr(rd)
    } else {
        crate::arch::aarch64::registers::w_or_zr(rd)
    };
    let src1 = if is_64 {
        crate::arch::aarch64::registers::x_or_zr(rn)
    } else {
        crate::arch::aarch64::registers::w_or_zr(rn)
    };
    let src2 = if is_64 {
        crate::arch::aarch64::registers::x_or_zr(rm)
    } else {
        crate::arch::aarch64::registers::w_or_zr(rm)
    };
    let mnemonic = if opc == 0b01 && rn == 31 {
        "mov"
    } else {
        match opc {
            0b00 => "and",
            0b01 => "orr",
            0b10 => "eor",
            _ => "ands",
        }
    };
    let operands = if mnemonic == "mov" {
        vec![Operand::Register(dst), Operand::Register(src2)]
    } else {
        vec![
            Operand::Register(dst),
            Operand::Register(src1),
            Operand::Register(src2),
        ]
    };
    base(
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
    )
}

fn decode_lsr_register(word: u32, address: u64) -> Instruction {
    let is_64 = bits(word, 31, 31) == 1;
    let rm = bits(word, 16, 20);
    let rn = bits(word, 5, 9);
    let rd = bits(word, 0, 4);
    let dst = if is_64 {
        crate::arch::aarch64::registers::x_or_zr(rd)
    } else {
        crate::arch::aarch64::registers::w_or_zr(rd)
    };
    let src = if is_64 {
        crate::arch::aarch64::registers::x_or_zr(rn)
    } else {
        crate::arch::aarch64::registers::w_or_zr(rn)
    };
    let shift = if is_64 {
        crate::arch::aarch64::registers::x_or_zr(rm)
    } else {
        crate::arch::aarch64::registers::w_or_zr(rm)
    };
    base(
        word,
        address,
        "lsr",
        vec![
            Operand::Register(dst),
            Operand::Register(src),
            Operand::Register(shift),
        ],
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        None,
    )
}

fn decode_logical_immediate(word: u32, address: u64) -> Instruction {
    let is_64 = bits(word, 31, 31) == 1;
    let opc = bits(word, 29, 30);
    let n = bits(word, 22, 22);
    let immr = bits(word, 16, 21);
    let imms = bits(word, 10, 15);
    let rn = bits(word, 5, 9);
    let rd = bits(word, 0, 4);
    let reg_size = if is_64 { 64 } else { 32 };
    let Some(mask) = decode_logical_immediate_mask(n, immr, imms, reg_size) else {
        return unknown(word, address);
    };

    let dst = if is_64 {
        crate::arch::aarch64::registers::x_or_zr(rd)
    } else {
        crate::arch::aarch64::registers::w_or_zr(rd)
    };
    let src = if is_64 {
        crate::arch::aarch64::registers::x_or_zr(rn)
    } else {
        crate::arch::aarch64::registers::w_or_zr(rn)
    };
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
    base(
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
    )
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
    let mut mask = 0u64;
    let mut shift = 0;
    while shift < reg_size {
        mask |= rotated << shift;
        shift += element_size;
    }
    Some(mask)
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

fn access_size_bytes(word: u32) -> i64 {
    1i64 << bits(word, 30, 31)
}

fn access_register(word: u32, rt: u32) -> crate::model::Register {
    if bits(word, 30, 31) == 0b11 {
        crate::arch::aarch64::registers::x(rt)
    } else {
        crate::arch::aarch64::registers::w(rt)
    }
}

fn pair_access_size_bytes(word: u32) -> Option<i64> {
    let vector = bits(word, 26, 26) == 1;
    let high = bits(word, 31, 31) == 1;
    match (vector, high) {
        (false, false) => Some(4),
        (false, true) => Some(8),
        (true, true) => Some(16),
        (true, false) => None,
    }
}

fn pair_access_register(word: u32, rt: u32) -> Option<crate::model::Register> {
    let vector = bits(word, 26, 26) == 1;
    let high = bits(word, 31, 31) == 1;
    match (vector, high) {
        (false, false) => Some(crate::arch::aarch64::registers::w_or_zr(rt)),
        (false, true) => Some(crate::arch::aarch64::registers::x_or_zr(rt)),
        (true, true) => Some(crate::arch::aarch64::registers::q(rt)),
        (true, false) => None,
    }
}

fn decode_load_store_unsigned(word: u32, address: u64) -> Instruction {
    let load = bits(word, 22, 22) == 1;
    let imm = i64::from(bits(word, 10, 21)) * access_size_bytes(word);
    let rn = bits(word, 5, 9);
    let rt = bits(word, 0, 4);
    let reg = access_register(word, rt);
    let base_reg = crate::arch::aarch64::registers::x_or_sp(rn);
    base(
        word,
        address,
        if load { "ldr" } else { "str" },
        vec![
            Operand::Register(reg),
            Operand::Memory(crate::model::MemoryOperand::base_offset(
                base_reg,
                imm,
                Some((access_size_bytes(word) * 8) as u16),
            )),
        ],
        if load {
            InstructionKind::Load
        } else {
            InstructionKind::Store
        },
        FlowKind::Fallthrough,
        None,
    )
}

fn decode_load_store_register_offset(word: u32, address: u64) -> Instruction {
    let load = bits(word, 22, 22) == 1;
    let size_bytes = access_size_bytes(word);
    let option = bits(word, 13, 15);
    let scaled = bits(word, 12, 12) == 1;
    if option != 0b010 {
        return unknown(word, address);
    }

    let rm = bits(word, 16, 20);
    let rn = bits(word, 5, 9);
    let rt = bits(word, 0, 4);
    let reg = access_register(word, rt);
    let base_reg = crate::arch::aarch64::registers::x_or_sp(rn);
    let index_reg = crate::arch::aarch64::registers::w(rm);
    let scale = if scaled { size_bytes as u8 } else { 1 };
    base(
        word,
        address,
        if load { "ldr" } else { "str" },
        vec![
            Operand::Register(reg),
            Operand::Memory(crate::model::MemoryOperand::indexed(
                Some(base_reg),
                Some(index_reg),
                scale,
                0,
                Some((size_bytes * 8) as u16),
            )),
        ],
        if load {
            InstructionKind::Load
        } else {
            InstructionKind::Store
        },
        FlowKind::Fallthrough,
        None,
    )
}

fn decode_load_store_pair(word: u32, address: u64) -> Instruction {
    let load = bits(word, 22, 22) == 1;
    let Some(size_bytes) = pair_access_size_bytes(word) else {
        return unknown(word, address);
    };
    let imm = sign_extend(bits(word, 15, 21), 7) * size_bytes;
    let post_index = bits(word, 23, 24) == 0b01;
    let pre_index = bits(word, 23, 24) == 0b11;
    let rt2 = bits(word, 10, 14);
    let rn = bits(word, 5, 9);
    let rt = bits(word, 0, 4);
    let Some(reg) = pair_access_register(word, rt) else {
        return unknown(word, address);
    };
    let Some(reg2) = pair_access_register(word, rt2) else {
        return unknown(word, address);
    };
    let base_reg = crate::arch::aarch64::registers::x_or_sp(rn);
    let mut memory =
        crate::model::MemoryOperand::base_offset(base_reg, imm, Some((size_bytes * 8) as u16));
    if pre_index {
        memory = memory.with_writeback();
    }
    if post_index {
        memory = memory.with_post_index();
    }
    base(
        word,
        address,
        if load { "ldp" } else { "stp" },
        vec![
            Operand::Register(reg),
            Operand::Register(reg2),
            Operand::Memory(memory),
        ],
        if load {
            InstructionKind::Load
        } else {
            InstructionKind::Store
        },
        FlowKind::Fallthrough,
        None,
    )
}

fn decode_load_store_unscaled(word: u32, address: u64) -> Instruction {
    let load = bits(word, 22, 22) == 1;
    let post_index = bits(word, 10, 11) == 0b01;
    let pre_index = bits(word, 10, 11) == 0b11;
    let imm = sign_extend(bits(word, 12, 20), 9);
    let rn = bits(word, 5, 9);
    let rt = bits(word, 0, 4);
    let reg = access_register(word, rt);
    let base_reg = crate::arch::aarch64::registers::x_or_sp(rn);
    let mut memory = crate::model::MemoryOperand::base_offset(
        base_reg,
        imm,
        Some((access_size_bytes(word) * 8) as u16),
    );
    if pre_index {
        memory = memory.with_writeback();
    }
    if post_index {
        memory = memory.with_post_index();
    }
    let mnemonic = match (load, pre_index || post_index) {
        (true, true) => "ldr",
        (false, true) => "str",
        (true, false) => "ldur",
        (false, false) => "stur",
    };
    base(
        word,
        address,
        mnemonic,
        vec![Operand::Register(reg), Operand::Memory(memory)],
        if load {
            InstructionKind::Load
        } else {
            InstructionKind::Store
        },
        FlowKind::Fallthrough,
        None,
    )
}

fn decode_brk(word: u32, address: u64) -> Instruction {
    let imm = bits(word, 5, 20);
    base(
        word,
        address,
        "brk",
        vec![Operand::Immediate(i64::from(imm))],
        InstructionKind::System,
        FlowKind::Fallthrough,
        None,
    )
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
