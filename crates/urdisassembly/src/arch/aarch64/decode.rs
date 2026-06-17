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
        mask: 0x1f80_0000,
        value: 0x1280_0000,
        decode: decode_move_wide,
    },
    Pattern {
        mask: 0x1f00_0000,
        value: 0x0a00_0000,
        decode: decode_logical_shifted_register,
    },
    Pattern {
        mask: 0x3b00_0000,
        value: 0x3900_0000,
        decode: decode_load_store_unsigned,
    },
    Pattern {
        mask: 0x3b20_0400,
        value: 0x3800_0400,
        decode: decode_load_store_unscaled,
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

fn decode_move_wide(word: u32, address: u64) -> Instruction {
    let is_64 = bits(word, 31, 31) == 1;
    let opc = bits(word, 29, 30);
    let hw = bits(word, 21, 22);
    let imm = i64::from(bits(word, 5, 20) << (hw * 16));
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
            Operand::Memory(crate::model::MemoryOperand {
                base: base_reg,
                offset: imm,
                writeback: false,
                post_index: false,
            }),
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
    base(
        word,
        address,
        if load { "ldr" } else { "str" },
        vec![
            Operand::Register(reg),
            Operand::Memory(crate::model::MemoryOperand {
                base: base_reg,
                offset: imm,
                writeback: pre_index,
                post_index,
            }),
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
