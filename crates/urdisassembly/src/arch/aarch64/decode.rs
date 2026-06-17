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
        if link { FlowKind::Call } else { FlowKind::Branch },
        Some(target),
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
