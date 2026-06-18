use crate::{
    arch::x86_64::{
        format::render_instruction,
        registers::{mm, reg16, reg32, reg64, reg8, xmm, ymm},
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
    operand_size_override: bool,
    repeat_prefix: Option<u8>,
    opcode_offset: usize,
}

#[derive(Debug, Clone, Copy)]
struct ModRm {
    mode: u8,
    reg: u8,
    rm: u8,
}

#[derive(Debug, Clone, Copy)]
struct Vex {
    rex: Rex,
    vvvv: u8,
    map: u8,
    pp: u8,
    l_256: bool,
    opcode_offset: usize,
}

pub fn decode_instruction(bytes: &[u8], address: u64) -> Result<Instruction> {
    let prefixes = parse_prefixes(bytes)?;
    let opcode_offset = prefixes.opcode_offset;
    let opcode = bytes[opcode_offset];
    match opcode {
        0xc2 => {
            let size = opcode_offset + 3;
            let imm = i64::from(read_u16(bytes, opcode_offset + 1)?);
            Ok(base(
                bytes[..size].to_vec(),
                address,
                "ret",
                vec![Operand::Immediate(imm)],
                InstructionKind::Return,
                FlowKind::Return,
                None,
            ))
        }
        0xc3 => Ok(base(
            bytes[..opcode_offset + 1].to_vec(),
            address,
            "ret",
            Vec::new(),
            InstructionKind::Return,
            FlowKind::Return,
            None,
        )),
        0xc8 => {
            let size = opcode_offset + 4;
            let frame_size = i64::from(read_u16(bytes, opcode_offset + 1)?);
            let nesting_level = i64::from(read_u8(bytes, opcode_offset + 3)?);
            Ok(base(
                bytes[..size].to_vec(),
                address,
                "enter",
                vec![
                    Operand::Immediate(frame_size),
                    Operand::Immediate(nesting_level),
                ],
                InstructionKind::Store,
                FlowKind::Fallthrough,
                None,
            ))
        }
        0xc9 => Ok(base(
            bytes[..opcode_offset + 1].to_vec(),
            address,
            "leave",
            Vec::new(),
            InstructionKind::Load,
            FlowKind::Fallthrough,
            None,
        )),
        0xca => {
            let size = opcode_offset + 3;
            let imm = i64::from(read_u16(bytes, opcode_offset + 1)?);
            Ok(base(
                bytes[..size].to_vec(),
                address,
                "retf",
                vec![Operand::Immediate(imm)],
                InstructionKind::Return,
                FlowKind::Return,
                None,
            ))
        }
        0xcb => Ok(base(
            bytes[..opcode_offset + 1].to_vec(),
            address,
            "retf",
            Vec::new(),
            InstructionKind::Return,
            FlowKind::Return,
            None,
        )),
        0xcc => Ok(base(
            bytes[..opcode_offset + 1].to_vec(),
            address,
            "int3",
            Vec::new(),
            InstructionKind::System,
            FlowKind::Fallthrough,
            None,
        )),
        0xcd => {
            let size = opcode_offset + 2;
            let imm = i64::from(read_u8(bytes, opcode_offset + 1)?);
            Ok(base(
                bytes[..size].to_vec(),
                address,
                "int",
                vec![Operand::Immediate(imm)],
                InstructionKind::System,
                FlowKind::Fallthrough,
                None,
            ))
        }
        0xf1 => Ok(base(
            bytes[..opcode_offset + 1].to_vec(),
            address,
            "int1",
            Vec::new(),
            InstructionKind::System,
            FlowKind::Fallthrough,
            None,
        )),
        0xf5 => Ok(base(
            bytes[..opcode_offset + 1].to_vec(),
            address,
            "cmc",
            Vec::new(),
            InstructionKind::Logical,
            FlowKind::Fallthrough,
            None,
        )),
        0xfb => Ok(base(
            bytes[..opcode_offset + 1].to_vec(),
            address,
            "sti",
            Vec::new(),
            InstructionKind::System,
            FlowKind::Fallthrough,
            None,
        )),
        0xcf => Ok(base(
            bytes[..opcode_offset + 1].to_vec(),
            address,
            if prefixes.rex.w { "iretq" } else { "iretd" },
            Vec::new(),
            InstructionKind::System,
            FlowKind::Return,
            None,
        )),
        0x90 => Ok(base(
            bytes[..opcode_offset + 1].to_vec(),
            address,
            "nop",
            Vec::new(),
            InstructionKind::System,
            FlowKind::Fallthrough,
            None,
        )),
        0x6c..=0x6f => decode_string_io(bytes, address, prefixes, opcode),
        0x91..=0x97 => decode_xchg_acc_reg(bytes, address, prefixes, opcode),
        0x98 => Ok(base(
            bytes[..opcode_offset + 1].to_vec(),
            address,
            mnemonic_for_acc_sign_extend(prefixes),
            Vec::new(),
            InstructionKind::Arithmetic,
            FlowKind::Fallthrough,
            None,
        )),
        0x99 => Ok(base(
            bytes[..opcode_offset + 1].to_vec(),
            address,
            mnemonic_for_dx_acc_sign_extend(prefixes),
            Vec::new(),
            InstructionKind::Arithmetic,
            FlowKind::Fallthrough,
            None,
        )),
        0x9c => Ok(base(
            bytes[..opcode_offset + 1].to_vec(),
            address,
            if prefixes.operand_size_override {
                "pushf"
            } else {
                "pushfq"
            },
            Vec::new(),
            InstructionKind::Store,
            FlowKind::Fallthrough,
            None,
        )),
        0x9d => Ok(base(
            bytes[..opcode_offset + 1].to_vec(),
            address,
            if prefixes.operand_size_override {
                "popf"
            } else {
                "popfq"
            },
            Vec::new(),
            InstructionKind::Load,
            FlowKind::Fallthrough,
            None,
        )),
        0x9e => Ok(base(
            bytes[..opcode_offset + 1].to_vec(),
            address,
            "sahf",
            Vec::new(),
            InstructionKind::Move,
            FlowKind::Fallthrough,
            None,
        )),
        0x9f => Ok(base(
            bytes[..opcode_offset + 1].to_vec(),
            address,
            "lahf",
            Vec::new(),
            InstructionKind::Move,
            FlowKind::Fallthrough,
            None,
        )),
        0xa8 => {
            let size = opcode_offset + 2;
            let imm = i64::from(read_u8(bytes, opcode_offset + 1)?);
            Ok(base(
                bytes[..size].to_vec(),
                address,
                "test",
                vec![
                    Operand::Register(reg8(0, prefixes.rex.present)),
                    Operand::Immediate(imm),
                ],
                InstructionKind::Compare,
                FlowKind::Fallthrough,
                None,
            ))
        }
        0xa9 => decode_acc_imm32(bytes, address, prefixes, "test", InstructionKind::Compare),
        0xa4..=0xa7 | 0xaa..=0xaf => decode_string_op(bytes, address, prefixes, opcode),
        0xe0..=0xe3 => decode_loop_rel8(bytes, address, prefixes, opcode),
        0xe4..=0xe7 | 0xec..=0xef => decode_io(bytes, address, prefixes, opcode),
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
            } else if (0x40..=0x4f).contains(&second) {
                decode_cmovcc(bytes, address, prefixes, second)
            } else if second == 0x1f {
                decode_multibyte_nop(bytes, address, prefixes)
            } else if second == 0x0b {
                Ok(base(
                    bytes[..opcode_offset + 2].to_vec(),
                    address,
                    "ud2",
                    Vec::new(),
                    InstructionKind::System,
                    FlowKind::Fallthrough,
                    None,
                ))
            } else if second == 0xa2 {
                Ok(base(
                    bytes[..opcode_offset + 2].to_vec(),
                    address,
                    "cpuid",
                    Vec::new(),
                    InstructionKind::System,
                    FlowKind::Fallthrough,
                    None,
                ))
            } else if second == 0x01 {
                decode_0f01_system(bytes, address, prefixes)
            } else if second == 0x6f || second == 0x7f {
                decode_mmx_move(bytes, address, prefixes, second)
            } else if second == 0x6e {
                decode_movd_movq_to_vector(bytes, address, prefixes)
            } else if second == 0x70 {
                decode_packed_shuffle(bytes, address, prefixes)
            } else if second == 0x7e {
                decode_movd_movq(bytes, address, prefixes)
            } else if second == 0x74 {
                decode_pcmpeqb(bytes, address, prefixes)
            } else if second == 0xae {
                decode_0fae_system(bytes, address, prefixes)
            } else if second == 0xb0 {
                decode_cmpxchg(bytes, address, prefixes, 8)
            } else if second == 0xb1 {
                decode_cmpxchg(bytes, address, prefixes, default_operand_width(prefixes))
            } else if second == 0xbc {
                decode_bsf(bytes, address, prefixes)
            } else if second == 0xc1 {
                decode_xadd(bytes, address, prefixes, default_operand_width(prefixes))
            } else if second == 0x73 {
                decode_packed_shift_imm(bytes, address, prefixes)
            } else if matches!(
                second,
                0x60 | 0x64 | 0xd7 | 0xdb | 0xe0 | 0xeb | 0xef | 0xf1 | 0xf5 | 0xfa | 0xfb | 0xfd
            ) {
                decode_mmx_opcode(bytes, address, prefixes, second)
            } else if second == 0xa3 {
                decode_bit_test_reg(bytes, address, prefixes, "bt", InstructionKind::Compare)
            } else if second == 0xab {
                decode_bit_test_reg(bytes, address, prefixes, "bts", InstructionKind::Logical)
            } else if second == 0xba {
                decode_bit_test_imm(bytes, address, prefixes)
            } else if matches!(second, 0x10 | 0x11 | 0x28 | 0x29) {
                decode_sse_move(bytes, address, prefixes, second)
            } else if second == 0x2d {
                decode_cvtps2pi(bytes, address, prefixes)
            } else if matches!(second, 0x2e | 0x2f) {
                decode_sse_compare_unordered(bytes, address, prefixes, second)
            } else if matches!(second, 0x54 | 0x56 | 0x58 | 0x5c | 0x5e) {
                decode_sse_binary(
                    bytes,
                    address,
                    prefixes,
                    mnemonic_for_sse_binary(second, prefixes),
                    if matches!(second, 0x54 | 0x56) {
                        InstructionKind::Logical
                    } else {
                        InstructionKind::Arithmetic
                    },
                )
            } else if second == 0x59 {
                let mnemonic = if prefixes.repeat_prefix == Some(0xf2) {
                    "mulsd"
                } else {
                    "mulps"
                };
                decode_sse_binary(
                    bytes,
                    address,
                    prefixes,
                    mnemonic,
                    InstructionKind::Arithmetic,
                )
            } else if second == 0x57 {
                decode_sse_binary(bytes, address, prefixes, "xorps", InstructionKind::Logical)
            } else if second == 0xc2 {
                decode_sse_compare(bytes, address, prefixes)
            } else if (0x90..=0x9f).contains(&second) {
                decode_setcc(bytes, address, prefixes, second)
            } else if second == 0xaf {
                decode_imul_rm(bytes, address, prefixes)
            } else if second == 0xb7 {
                decode_movzx_word(bytes, address, prefixes)
            } else if second == 0xbd {
                decode_bit_scan(bytes, address, prefixes, "bsr")
            } else if second == 0xb6 || second == 0xbe {
                decode_mov_extend(bytes, address, prefixes, second)
            } else if (0xc8..=0xcf).contains(&second) {
                decode_bswap(bytes, address, prefixes, second)
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
        0xb0..=0xb7 => {
            let size = opcode_offset + 2;
            let reg = extend_reg(opcode - 0xb0, prefixes.rex.b);
            let imm = i64::from(read_u8(bytes, opcode_offset + 1)?);
            Ok(base(
                bytes[..size].to_vec(),
                address,
                "mov",
                vec![
                    Operand::Register(reg8(reg, prefixes.rex.present)),
                    Operand::Immediate(imm),
                ],
                InstructionKind::Move,
                FlowKind::Fallthrough,
                None,
            ))
        }
        0x63 => decode_movsxd(bytes, address, prefixes),
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
        0x88 | 0x8a => decode_byte_mov(bytes, address, prefixes, opcode),
        0x00 => decode_reg_rm_binary_width(
            bytes,
            address,
            prefixes,
            "add",
            InstructionKind::Arithmetic,
            false,
            8,
        ),
        0x02 => decode_reg_rm_binary_width(
            bytes,
            address,
            prefixes,
            "add",
            InstructionKind::Arithmetic,
            true,
            8,
        ),
        0x04 => decode_al_imm8(bytes, address, prefixes, "add", InstructionKind::Arithmetic),
        0x05 => decode_acc_imm32(bytes, address, prefixes, "add", InstructionKind::Arithmetic),
        0x0d => decode_acc_imm32(bytes, address, prefixes, "or", InstructionKind::Logical),
        0x15 => decode_acc_imm32(bytes, address, prefixes, "adc", InstructionKind::Arithmetic),
        0x1d => decode_acc_imm32(bytes, address, prefixes, "sbb", InstructionKind::Arithmetic),
        0x35 => decode_acc_imm32(bytes, address, prefixes, "xor", InstructionKind::Logical),
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
        0x10 => decode_reg_rm_binary_width(
            bytes,
            address,
            prefixes,
            "adc",
            InstructionKind::Arithmetic,
            false,
            8,
        ),
        0x12 => decode_reg_rm_binary_width(
            bytes,
            address,
            prefixes,
            "adc",
            InstructionKind::Arithmetic,
            true,
            8,
        ),
        0x11 => decode_reg_rm_binary_default_width(
            bytes,
            address,
            prefixes,
            "adc",
            InstructionKind::Arithmetic,
            false,
        ),
        0x13 => decode_reg_rm_binary_default_width(
            bytes,
            address,
            prefixes,
            "adc",
            InstructionKind::Arithmetic,
            true,
        ),
        0x14 => decode_al_imm8(bytes, address, prefixes, "adc", InstructionKind::Arithmetic),
        0x08 => decode_reg_rm_binary_width(
            bytes,
            address,
            prefixes,
            "or",
            InstructionKind::Logical,
            false,
            8,
        ),
        0x0a => decode_reg_rm_binary_width(
            bytes,
            address,
            prefixes,
            "or",
            InstructionKind::Logical,
            true,
            8,
        ),
        0x0c => decode_al_imm8(bytes, address, prefixes, "or", InstructionKind::Logical),
        0x18 => decode_reg_rm_binary_width(
            bytes,
            address,
            prefixes,
            "sbb",
            InstructionKind::Arithmetic,
            false,
            8,
        ),
        0x1a => decode_reg_rm_binary_width(
            bytes,
            address,
            prefixes,
            "sbb",
            InstructionKind::Arithmetic,
            true,
            8,
        ),
        0x19 => decode_reg_rm_binary_default_width(
            bytes,
            address,
            prefixes,
            "sbb",
            InstructionKind::Arithmetic,
            false,
        ),
        0x1b => decode_reg_rm_binary_default_width(
            bytes,
            address,
            prefixes,
            "sbb",
            InstructionKind::Arithmetic,
            true,
        ),
        0x1c => decode_al_imm8(bytes, address, prefixes, "sbb", InstructionKind::Arithmetic),
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
        0x28 => decode_reg_rm_binary_width(
            bytes,
            address,
            prefixes,
            "sub",
            InstructionKind::Arithmetic,
            false,
            8,
        ),
        0x2a => decode_reg_rm_binary_width(
            bytes,
            address,
            prefixes,
            "sub",
            InstructionKind::Arithmetic,
            true,
            8,
        ),
        0x2c => decode_al_imm8(bytes, address, prefixes, "sub", InstructionKind::Arithmetic),
        0x2d => decode_acc_imm32(bytes, address, prefixes, "sub", InstructionKind::Arithmetic),
        0x20 => decode_reg_rm_binary_width(
            bytes,
            address,
            prefixes,
            "and",
            InstructionKind::Logical,
            false,
            8,
        ),
        0x22 => decode_reg_rm_binary_width(
            bytes,
            address,
            prefixes,
            "and",
            InstructionKind::Logical,
            true,
            8,
        ),
        0x24 => decode_al_imm8(bytes, address, prefixes, "and", InstructionKind::Logical),
        0x25 => decode_acc_imm32(bytes, address, prefixes, "and", InstructionKind::Logical),
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
        0x30 => decode_reg_rm_binary_width(
            bytes,
            address,
            prefixes,
            "xor",
            InstructionKind::Logical,
            false,
            8,
        ),
        0x32 => decode_reg_rm_binary_width(
            bytes,
            address,
            prefixes,
            "xor",
            InstructionKind::Logical,
            true,
            8,
        ),
        0x34 => decode_al_imm8(bytes, address, prefixes, "xor", InstructionKind::Logical),
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
        0x38 => decode_reg_rm_binary_width(
            bytes,
            address,
            prefixes,
            "cmp",
            InstructionKind::Compare,
            false,
            8,
        ),
        0x3a => decode_reg_rm_binary_width(
            bytes,
            address,
            prefixes,
            "cmp",
            InstructionKind::Compare,
            true,
            8,
        ),
        0x3c => decode_al_imm8(bytes, address, prefixes, "cmp", InstructionKind::Compare),
        0x3d => decode_acc_imm32(bytes, address, prefixes, "cmp", InstructionKind::Compare),
        0x69 => decode_imul_imm(bytes, address, prefixes, 32),
        0x6b => decode_imul_imm(bytes, address, prefixes, 8),
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
        0x84 => decode_reg_rm_binary_width(
            bytes,
            address,
            prefixes,
            "test",
            InstructionKind::Compare,
            false,
            8,
        ),
        0x80 => decode_group1_imm8_width(bytes, address, prefixes, 8, false),
        0x81 => decode_group1_imm32(bytes, address, prefixes),
        0x83 => decode_group1_imm8(bytes, address, prefixes),
        0x86 => decode_xchg_width(bytes, address, prefixes, 8),
        0x87 => decode_xchg(bytes, address, prefixes),
        0xc4 | 0xc5 => decode_vex(bytes, address, prefixes),
        0xc0 => decode_group2_imm8(bytes, address, prefixes, 8),
        0xc1 => decode_group2_imm8(bytes, address, prefixes, default_operand_width(prefixes)),
        0xd0 => decode_group2_one(bytes, address, prefixes, 8),
        0xd1 => decode_group2_one(bytes, address, prefixes, default_operand_width(prefixes)),
        0xd2 => decode_group2_cl(bytes, address, prefixes, 8),
        0xd3 => decode_group2_cl(bytes, address, prefixes, default_operand_width(prefixes)),
        0xda | 0xdb | 0xdd => decode_x87_memory(bytes, address, prefixes, opcode),
        0xc6 => decode_mov_imm8_rm(bytes, address, prefixes),
        0xc7 => decode_mov_imm_rm(bytes, address, prefixes),
        0xfe => decode_group_fe(bytes, address, prefixes),
        0xf6 => decode_group_f6(bytes, address, prefixes),
        0xf7 => decode_group_f7(bytes, address, prefixes),
        0xff => decode_group_ff(bytes, address, prefixes),
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

fn decode_reg_rm_binary_default_width(
    bytes: &[u8],
    address: u64,
    prefixes: Prefixes,
    mnemonic: &str,
    kind: InstructionKind,
    reg_is_dst: bool,
) -> Result<Instruction> {
    decode_reg_rm_binary_width(
        bytes,
        address,
        prefixes,
        mnemonic,
        kind,
        reg_is_dst,
        default_operand_width(prefixes),
    )
}

fn decode_reg_rm_binary_width(
    bytes: &[u8],
    address: u64,
    prefixes: Prefixes,
    mnemonic: &str,
    kind: InstructionKind,
    reg_is_dst: bool,
    width_bits: u16,
) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 1;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let reg = Operand::Register(reg_for_width(
        extend_reg(modrm.reg, prefixes.rex.r),
        width_bits,
        prefixes.rex.present,
    ));
    let (rm, consumed) = parse_rm_operand(bytes, modrm_offset, prefixes.rex, width_bits)?;
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

fn decode_movsxd(bytes: &[u8], address: u64, prefixes: Prefixes) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 1;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let dst_width = default_operand_width(prefixes);
    let dst = Operand::Register(reg_for_width(
        extend_reg(modrm.reg, prefixes.rex.r),
        dst_width,
        prefixes.rex.present,
    ));
    let (src, consumed) = parse_rm_operand(bytes, modrm_offset, prefixes.rex, 32)?;
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        "movsxd",
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

fn decode_byte_mov(
    bytes: &[u8],
    address: u64,
    prefixes: Prefixes,
    opcode: u8,
) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 1;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let reg = Operand::Register(reg8(
        extend_reg(modrm.reg, prefixes.rex.r),
        prefixes.rex.present,
    ));
    let (rm, consumed) = parse_rm_operand(bytes, modrm_offset, prefixes.rex, 8)?;
    let reg_is_dst = opcode == 0x8a;
    let operands = if reg_is_dst {
        vec![reg, rm.clone()]
    } else {
        vec![rm.clone(), reg]
    };
    let kind = match (reg_is_dst, matches!(rm, Operand::Memory(_))) {
        (true, true) => InstructionKind::Load,
        (false, true) => InstructionKind::Store,
        _ => InstructionKind::Move,
    };
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        "mov",
        operands,
        kind,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_acc_imm32(
    bytes: &[u8],
    address: u64,
    prefixes: Prefixes,
    mnemonic: &str,
    kind: InstructionKind,
) -> Result<Instruction> {
    let size = prefixes.opcode_offset + 5;
    let imm = if prefixes.rex.w {
        i64::from(read_i32(bytes, prefixes.opcode_offset + 1)?)
    } else {
        i64::from(read_u32(bytes, prefixes.opcode_offset + 1)?)
    };
    Ok(base(
        bytes[..size].to_vec(),
        address,
        mnemonic,
        vec![
            Operand::Register(reg_for_width(
                0,
                default_operand_width(prefixes),
                prefixes.rex.present,
            )),
            Operand::Immediate(imm),
        ],
        kind,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_al_imm8(
    bytes: &[u8],
    address: u64,
    prefixes: Prefixes,
    mnemonic: &str,
    kind: InstructionKind,
) -> Result<Instruction> {
    let size = prefixes.opcode_offset + 2;
    let imm = i64::from(read_u8(bytes, prefixes.opcode_offset + 1)?);
    Ok(base(
        bytes[..size].to_vec(),
        address,
        mnemonic,
        vec![
            Operand::Register(reg8(0, prefixes.rex.present)),
            Operand::Immediate(imm),
        ],
        kind,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_xchg(bytes: &[u8], address: u64, prefixes: Prefixes) -> Result<Instruction> {
    decode_xchg_width(bytes, address, prefixes, default_operand_width(prefixes))
}

fn decode_xchg_width(
    bytes: &[u8],
    address: u64,
    prefixes: Prefixes,
    width_bits: u16,
) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 1;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let reg = Operand::Register(reg_for_width(
        extend_reg(modrm.reg, prefixes.rex.r),
        width_bits,
        prefixes.rex.present,
    ));
    let (rm, consumed) = parse_rm_operand(bytes, modrm_offset, prefixes.rex, width_bits)?;
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        "xchg",
        vec![rm, reg],
        InstructionKind::Move,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_xchg_acc_reg(
    bytes: &[u8],
    address: u64,
    prefixes: Prefixes,
    opcode: u8,
) -> Result<Instruction> {
    let width_bits = default_operand_width(prefixes);
    let reg = Operand::Register(reg_for_width(
        extend_reg(opcode - 0x90, prefixes.rex.b),
        width_bits,
        prefixes.rex.present,
    ));
    let acc = Operand::Register(reg_for_width(0, width_bits, prefixes.rex.present));
    Ok(base(
        bytes[..prefixes.opcode_offset + 1].to_vec(),
        address,
        "xchg",
        vec![reg, acc],
        InstructionKind::Move,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_string_op(
    bytes: &[u8],
    address: u64,
    prefixes: Prefixes,
    opcode: u8,
) -> Result<Instruction> {
    let width_bits = match opcode {
        0xa4 | 0xa6 | 0xaa | 0xac | 0xae => 8,
        _ => default_operand_width(prefixes),
    };
    let destination = Operand::Memory(MemoryOperand::base_offset(reg64(7), 0, Some(width_bits)));
    let source = Operand::Memory(MemoryOperand::base_offset(reg64(6), 0, Some(width_bits)));
    let accumulator = Operand::Register(reg_for_width(0, width_bits, prefixes.rex.present));
    let (mnemonic, operands, kind) = match opcode {
        0xa4 => ("movsb", vec![destination, source], InstructionKind::Move),
        0xa5 => (
            mnemonic_for_string_sized("movs", width_bits),
            vec![destination, source],
            InstructionKind::Move,
        ),
        0xa6 => ("cmpsb", vec![source, destination], InstructionKind::Compare),
        0xa7 => (
            mnemonic_for_string_sized("cmps", width_bits),
            vec![source, destination],
            InstructionKind::Compare,
        ),
        0xaa => (
            "stosb",
            vec![destination, accumulator],
            InstructionKind::Store,
        ),
        0xab => (
            mnemonic_for_string_sized("stos", width_bits),
            vec![destination, accumulator],
            InstructionKind::Store,
        ),
        0xac => ("lodsb", vec![accumulator, source], InstructionKind::Load),
        0xad => (
            mnemonic_for_string_sized("lods", width_bits),
            vec![accumulator, source],
            InstructionKind::Load,
        ),
        0xae => (
            "scasb",
            vec![accumulator, destination],
            InstructionKind::Compare,
        ),
        _ => (
            mnemonic_for_string_sized("scas", width_bits),
            vec![accumulator, destination],
            InstructionKind::Compare,
        ),
    };
    Ok(base(
        bytes[..prefixes.opcode_offset + 1].to_vec(),
        address,
        mnemonic,
        operands,
        kind,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_string_io(
    bytes: &[u8],
    address: u64,
    prefixes: Prefixes,
    opcode: u8,
) -> Result<Instruction> {
    let width_bits = match opcode {
        0x6c | 0x6e => 8,
        _ if prefixes.operand_size_override => 16,
        _ => 32,
    };
    let destination = Operand::Memory(MemoryOperand::base_offset(reg64(7), 0, Some(width_bits)));
    let source = Operand::Memory(MemoryOperand::base_offset(reg64(6), 0, Some(width_bits)));
    let dx = Operand::Register(reg16(2));
    let (mnemonic, operands) = match opcode {
        0x6c => ("insb", vec![destination, dx]),
        0x6d => (
            if width_bits == 16 { "insw" } else { "insd" },
            vec![destination, dx],
        ),
        0x6e => ("outsb", vec![dx, source]),
        _ => (
            if width_bits == 16 { "outsw" } else { "outsd" },
            vec![dx, source],
        ),
    };
    Ok(base(
        bytes[..prefixes.opcode_offset + 1].to_vec(),
        address,
        mnemonic,
        operands,
        InstructionKind::System,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_loop_rel8(
    bytes: &[u8],
    address: u64,
    prefixes: Prefixes,
    opcode: u8,
) -> Result<Instruction> {
    let size = prefixes.opcode_offset + 2;
    let disp = i64::from(read_i8(bytes, prefixes.opcode_offset + 1)?);
    let target = rel_target(address, size, disp);
    let mnemonic = match opcode {
        0xe0 => "loopne",
        0xe1 => "loope",
        0xe2 => "loop",
        _ => "jrcxz",
    };
    Ok(base(
        bytes[..size].to_vec(),
        address,
        mnemonic,
        absolute_target(target),
        InstructionKind::Branch,
        FlowKind::ConditionalBranch,
        Some(target),
    ))
}

fn decode_io(bytes: &[u8], address: u64, prefixes: Prefixes, opcode: u8) -> Result<Instruction> {
    let acc_width_bits = if prefixes.operand_size_override {
        16
    } else {
        32
    };
    let al = Operand::Register(reg8(0, prefixes.rex.present));
    let acc = Operand::Register(reg_for_width(0, acc_width_bits, prefixes.rex.present));
    let dx = Operand::Register(reg16(2));
    let (size, operands) = match opcode {
        0xe4 => (
            prefixes.opcode_offset + 2,
            vec![
                al,
                Operand::Immediate(i64::from(read_u8(bytes, prefixes.opcode_offset + 1)?)),
            ],
        ),
        0xe5 => (
            prefixes.opcode_offset + 2,
            vec![
                acc,
                Operand::Immediate(i64::from(read_u8(bytes, prefixes.opcode_offset + 1)?)),
            ],
        ),
        0xe6 => (
            prefixes.opcode_offset + 2,
            vec![
                Operand::Immediate(i64::from(read_u8(bytes, prefixes.opcode_offset + 1)?)),
                al,
            ],
        ),
        0xe7 => (
            prefixes.opcode_offset + 2,
            vec![
                Operand::Immediate(i64::from(read_u8(bytes, prefixes.opcode_offset + 1)?)),
                acc,
            ],
        ),
        0xec => (prefixes.opcode_offset + 1, vec![al, dx]),
        0xed => (prefixes.opcode_offset + 1, vec![acc, dx]),
        0xee => (prefixes.opcode_offset + 1, vec![dx, al]),
        _ => (prefixes.opcode_offset + 1, vec![dx, acc]),
    };
    let mnemonic = if matches!(opcode, 0xe4 | 0xe5 | 0xec | 0xed) {
        "in"
    } else {
        "out"
    };
    Ok(base(
        bytes[..size].to_vec(),
        address,
        mnemonic,
        operands,
        InstructionKind::System,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_group1_imm8(bytes: &[u8], address: u64, prefixes: Prefixes) -> Result<Instruction> {
    decode_group1_imm8_width(bytes, address, prefixes, 64, true)
}

fn decode_group1_imm8_width(
    bytes: &[u8],
    address: u64,
    prefixes: Prefixes,
    width_bits: u16,
    sign_extend: bool,
) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 1;
    require_len(bytes, modrm_offset + 2)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let (rm, consumed_without_imm) =
        parse_rm_operand(bytes, modrm_offset, prefixes.rex, width_bits)?;
    let imm = if sign_extend {
        i64::from(read_i8(bytes, consumed_without_imm)?)
    } else {
        i64::from(read_u8(bytes, consumed_without_imm)?)
    };
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

fn decode_group1_imm32(bytes: &[u8], address: u64, prefixes: Prefixes) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 1;
    require_len(bytes, modrm_offset + 5)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let (rm, consumed_without_imm) = parse_rm_operand(bytes, modrm_offset, prefixes.rex, 64)?;
    let imm = i64::from(read_i32(bytes, consumed_without_imm)?);
    let consumed = consumed_without_imm + 4;
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

fn decode_group2_imm8(
    bytes: &[u8],
    address: u64,
    prefixes: Prefixes,
    width_bits: u16,
) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 1;
    require_len(bytes, modrm_offset + 2)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let (rm, consumed_without_imm) =
        parse_rm_operand(bytes, modrm_offset, prefixes.rex, width_bits)?;
    let imm = i64::from(read_u8(bytes, consumed_without_imm)?);
    let consumed = consumed_without_imm + 1;
    let mnemonic = group2_mnemonic(modrm.reg);
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        mnemonic,
        vec![rm, Operand::Immediate(imm)],
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_group2_one(
    bytes: &[u8],
    address: u64,
    prefixes: Prefixes,
    width_bits: u16,
) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 1;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let (rm, consumed) = parse_rm_operand(bytes, modrm_offset, prefixes.rex, width_bits)?;
    let mnemonic = group2_mnemonic(modrm.reg);
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        mnemonic,
        vec![rm, Operand::Immediate(1)],
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_group2_cl(
    bytes: &[u8],
    address: u64,
    prefixes: Prefixes,
    width_bits: u16,
) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 1;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let (rm, consumed) = parse_rm_operand(bytes, modrm_offset, prefixes.rex, width_bits)?;
    let mnemonic = group2_mnemonic(modrm.reg);
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        mnemonic,
        vec![rm, Operand::Register(reg8(1, prefixes.rex.present))],
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_mov_imm8_rm(bytes: &[u8], address: u64, prefixes: Prefixes) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 1;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    if modrm.reg != 0 {
        return Ok(unknown(bytes[prefixes.opcode_offset], address));
    }
    let (rm, consumed_without_imm) = parse_rm_operand(bytes, modrm_offset, prefixes.rex, 8)?;
    let imm = i64::from(read_u8(bytes, consumed_without_imm)?);
    let consumed = consumed_without_imm + 1;
    let kind = if matches!(rm, Operand::Memory(_)) {
        InstructionKind::Store
    } else {
        InstructionKind::Move
    };
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        "mov",
        vec![rm, Operand::Immediate(imm)],
        kind,
        FlowKind::Fallthrough,
        None,
    ))
}

fn group2_mnemonic(reg: u8) -> &'static str {
    match reg {
        0 => "rol",
        1 => "ror",
        2 => "rcl",
        3 => "rcr",
        4 | 6 => "shl",
        5 => "shr",
        7 => "sar",
        _ => unreachable!("ModRM reg field is three bits"),
    }
}

fn decode_group_f6(bytes: &[u8], address: u64, prefixes: Prefixes) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 1;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let (rm, consumed_without_imm) = parse_rm_operand(bytes, modrm_offset, prefixes.rex, 8)?;
    if modrm.reg <= 1 {
        let imm = i64::from(read_u8(bytes, consumed_without_imm)?);
        let consumed = consumed_without_imm + 1;
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

fn decode_group_fe(bytes: &[u8], address: u64, prefixes: Prefixes) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 1;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let mnemonic = match modrm.reg {
        0 => "inc",
        1 => "dec",
        _ => return Ok(unknown(bytes[prefixes.opcode_offset], address)),
    };
    let (rm, consumed) = parse_rm_operand(bytes, modrm_offset, prefixes.rex, 8)?;
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        mnemonic,
        vec![rm],
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_x87_memory(
    bytes: &[u8],
    address: u64,
    prefixes: Prefixes,
    opcode: u8,
) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 1;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    if modrm.mode == 0b11 {
        return Ok(unknown(bytes[prefixes.opcode_offset], address));
    }
    let (mnemonic, width_bits, kind) = match (opcode, modrm.reg) {
        (0xda, 1) => ("fimul", 32, InstructionKind::Arithmetic),
        (0xdb, 3) => ("fistp", 32, InstructionKind::Store),
        (0xdd, 1) => ("fisttp", 64, InstructionKind::Store),
        (0xdd, 3) => ("fstp", 64, InstructionKind::Store),
        _ => return Ok(unknown(bytes[prefixes.opcode_offset], address)),
    };
    let (rm, consumed) = parse_rm_operand(bytes, modrm_offset, prefixes.rex, width_bits)?;
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        mnemonic,
        vec![rm],
        kind,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_mov_imm_rm(bytes: &[u8], address: u64, prefixes: Prefixes) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 1;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    if modrm.reg != 0 {
        return Ok(unknown(bytes[prefixes.opcode_offset], address));
    }
    let width_bits = if prefixes.operand_size_override {
        16
    } else {
        64
    };
    let (rm, consumed_without_imm) =
        parse_rm_operand(bytes, modrm_offset, prefixes.rex, width_bits)?;
    let (imm, consumed) = if prefixes.operand_size_override {
        (
            i64::from(read_i16(bytes, consumed_without_imm)?),
            consumed_without_imm + 2,
        )
    } else {
        (
            i64::from(read_i32(bytes, consumed_without_imm)?),
            consumed_without_imm + 4,
        )
    };
    let kind = if matches!(rm, Operand::Memory(_)) {
        InstructionKind::Store
    } else {
        InstructionKind::Move
    };
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        "mov",
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

fn decode_group_ff(bytes: &[u8], address: u64, prefixes: Prefixes) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 1;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let (rm, consumed) = parse_rm_operand(bytes, modrm_offset, prefixes.rex, 64)?;
    let (mnemonic, kind, flow) = match modrm.reg {
        0 => ("inc", InstructionKind::Arithmetic, FlowKind::Fallthrough),
        1 => ("dec", InstructionKind::Arithmetic, FlowKind::Fallthrough),
        2 => ("call", InstructionKind::Call, FlowKind::IndirectCall),
        4 => ("jmp", InstructionKind::Branch, FlowKind::IndirectBranch),
        6 => ("push", InstructionKind::Store, FlowKind::Fallthrough),
        _ => return Ok(unknown(bytes[prefixes.opcode_offset], address)),
    };
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        mnemonic,
        vec![rm],
        kind,
        flow,
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

fn decode_0f01_system(bytes: &[u8], address: u64, prefixes: Prefixes) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 2;
    require_len(bytes, modrm_offset + 1)?;
    if bytes[modrm_offset] != 0xd0 {
        return Ok(unknown(bytes[prefixes.opcode_offset], address));
    }
    Ok(base(
        bytes[..modrm_offset + 1].to_vec(),
        address,
        "xgetbv",
        Vec::new(),
        InstructionKind::System,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_0fae_system(bytes: &[u8], address: u64, prefixes: Prefixes) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 2;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    if modrm.mode != 0b11 && matches!(modrm.reg, 0x2 | 0x3) {
        let (mem, consumed) = parse_rm_operand(bytes, modrm_offset, prefixes.rex, 32)?;
        let mnemonic = if modrm.reg == 0x2 {
            "ldmxcsr"
        } else {
            "stmxcsr"
        };
        return Ok(base(
            bytes[..consumed].to_vec(),
            address,
            mnemonic,
            vec![mem],
            InstructionKind::System,
            FlowKind::Fallthrough,
            None,
        ));
    }
    if bytes[modrm_offset] == 0xf8 {
        return Ok(base(
            bytes[..modrm_offset + 1].to_vec(),
            address,
            "sfence",
            Vec::new(),
            InstructionKind::System,
            FlowKind::Fallthrough,
            None,
        ));
    }
    Ok(unknown(bytes[prefixes.opcode_offset], address))
}

fn decode_vex(bytes: &[u8], address: u64, prefixes: Prefixes) -> Result<Instruction> {
    let vex = parse_vex(bytes, prefixes.opcode_offset)?;
    require_len(bytes, vex.opcode_offset + 1)?;
    match vex.map {
        0x01 => decode_vex_map1(bytes, address, prefixes, vex),
        0x02 => decode_vex_map2(bytes, address, prefixes, vex),
        0x03 => decode_vex_map3(bytes, address, prefixes, vex),
        _ => Ok(unknown(bytes[prefixes.opcode_offset], address)),
    }
}

fn decode_vex_map1(
    bytes: &[u8],
    address: u64,
    prefixes: Prefixes,
    vex: Vex,
) -> Result<Instruction> {
    let opcode = bytes[vex.opcode_offset];
    match opcode {
        0x77 if vex.pp == 0 => Ok(base(
            bytes[..vex.opcode_offset + 1].to_vec(),
            address,
            "vzeroupper",
            Vec::new(),
            InstructionKind::System,
            FlowKind::Fallthrough,
            None,
        )),
        0x10 if vex.pp == 3 => decode_vex_reg_rm_move(bytes, address, vex, "vmovsd"),
        0x2f if vex.pp == 1 => {
            decode_vex_binary(bytes, address, vex, "vcomisd", InstructionKind::Compare)
        }
        0x28 if vex.pp == 1 => decode_vex_reg_rm_move(bytes, address, vex, "vmovapd"),
        0x6f | 0x7f if matches!(vex.pp, 1 | 2) => decode_vex_move(bytes, address, vex, opcode),
        0x7e if vex.pp == 1 => decode_vex_movd_movq_to_gpr(bytes, address, vex),
        0x73 if vex.pp == 1 => decode_vex_packed_shift_imm(bytes, address, vex),
        0xd4 if vex.pp == 1 => {
            decode_vex_ternary_binary(bytes, address, vex, "vpaddq", InstructionKind::Arithmetic)
        }
        0xe7 if vex.pp == 1 => decode_vex_movntdq(bytes, address, vex),
        0xe6 if matches!(vex.pp, 2 | 3) => decode_vex_binary(
            bytes,
            address,
            vex,
            "vcvtdq2pd",
            InstructionKind::Arithmetic,
        ),
        0xd7 if vex.pp == 1 => decode_vex_pmovmskb(bytes, address, vex),
        0x58 if vex.pp == 3 => {
            decode_vex_ternary_binary(bytes, address, vex, "vaddsd", InstructionKind::Arithmetic)
        }
        0x59 if matches!(vex.pp, 0 | 3) => decode_vex_ternary_binary(
            bytes,
            address,
            vex,
            if vex.pp == 3 { "vmulsd" } else { "vmulps" },
            InstructionKind::Arithmetic,
        ),
        0x5c if vex.pp == 3 => {
            decode_vex_ternary_binary(bytes, address, vex, "vsubsd", InstructionKind::Arithmetic)
        }
        0x5e if vex.pp == 3 => {
            decode_vex_ternary_binary(bytes, address, vex, "vdivsd", InstructionKind::Arithmetic)
        }
        0xdb if vex.pp == 1 => {
            decode_vex_ternary_binary(bytes, address, vex, "vpand", InstructionKind::Logical)
        }
        0xeb if vex.pp == 1 => {
            decode_vex_ternary_binary(bytes, address, vex, "vpor", InstructionKind::Logical)
        }
        0xef if vex.pp == 1 => {
            decode_vex_ternary_binary(bytes, address, vex, "vpxor", InstructionKind::Logical)
        }
        0xfa if vex.pp == 1 => {
            decode_vex_ternary_binary(bytes, address, vex, "vpsubd", InstructionKind::Arithmetic)
        }
        0xfb if vex.pp == 1 => {
            decode_vex_ternary_binary(bytes, address, vex, "vpsubq", InstructionKind::Arithmetic)
        }
        _ => Ok(unknown(bytes[prefixes.opcode_offset], address)),
    }
}

fn decode_vex_map2(
    bytes: &[u8],
    address: u64,
    prefixes: Prefixes,
    vex: Vex,
) -> Result<Instruction> {
    let opcode = bytes[vex.opcode_offset];
    match opcode {
        0xab if vex.pp == 1 => decode_vex_ternary_binary(
            bytes,
            address,
            vex,
            "vfmsub213sd",
            InstructionKind::Arithmetic,
        ),
        0xb9 if vex.pp == 1 => decode_vex_ternary_binary(
            bytes,
            address,
            vex,
            "vfmadd231sd",
            InstructionKind::Arithmetic,
        ),
        _ => Ok(unknown(bytes[prefixes.opcode_offset], address)),
    }
}

fn decode_vex_map3(
    bytes: &[u8],
    address: u64,
    prefixes: Prefixes,
    vex: Vex,
) -> Result<Instruction> {
    let opcode = bytes[vex.opcode_offset];
    match opcode {
        0x18 if vex.pp == 1 => decode_vinsertf128(bytes, address, vex),
        _ => Ok(unknown(bytes[prefixes.opcode_offset], address)),
    }
}

fn decode_vex_reg_rm_move(
    bytes: &[u8],
    address: u64,
    vex: Vex,
    mnemonic: &str,
) -> Result<Instruction> {
    let modrm_offset = vex.opcode_offset + 1;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let dst = Operand::Register(vector_reg(extend_reg(modrm.reg, vex.rex.r), vex));
    let (src, consumed) = parse_vector_rm_operand(bytes, modrm_offset, vex)?;
    let kind = if matches!(src, Operand::Memory(_)) {
        InstructionKind::Load
    } else {
        InstructionKind::Move
    };
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        mnemonic,
        vec![dst, src],
        kind,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_vex_move(bytes: &[u8], address: u64, vex: Vex, opcode: u8) -> Result<Instruction> {
    let modrm_offset = vex.opcode_offset + 1;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let reg = Operand::Register(vector_reg(extend_reg(modrm.reg, vex.rex.r), vex));
    let (rm, consumed) = parse_vector_rm_operand(bytes, modrm_offset, vex)?;
    let is_store = opcode == 0x7f;
    let operands = if is_store {
        vec![rm.clone(), reg]
    } else {
        vec![reg, rm.clone()]
    };
    let mnemonic = if vex.pp == 1 { "vmovdqa" } else { "vmovdqu" };
    let kind = match (is_store, matches!(rm, Operand::Memory(_))) {
        (true, true) => InstructionKind::Store,
        (false, true) => InstructionKind::Load,
        _ => InstructionKind::Move,
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

fn decode_vex_movntdq(bytes: &[u8], address: u64, vex: Vex) -> Result<Instruction> {
    let modrm_offset = vex.opcode_offset + 1;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let src = Operand::Register(vector_reg(extend_reg(modrm.reg, vex.rex.r), vex));
    let (dst, consumed) = parse_vector_rm_operand(bytes, modrm_offset, vex)?;
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        "vmovntdq",
        vec![dst, src],
        InstructionKind::Store,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_vex_pmovmskb(bytes: &[u8], address: u64, vex: Vex) -> Result<Instruction> {
    let modrm_offset = vex.opcode_offset + 1;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let dst = Operand::Register(reg32(extend_reg(modrm.reg, vex.rex.r)));
    let (src, consumed) = parse_vector_rm_operand(bytes, modrm_offset, vex)?;
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        "vpmovmskb",
        vec![dst, src],
        InstructionKind::Move,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_vex_movd_movq_to_gpr(bytes: &[u8], address: u64, vex: Vex) -> Result<Instruction> {
    let modrm_offset = vex.opcode_offset + 1;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let width_bits = if vex.rex.w { 64 } else { 32 };
    let dst = Operand::Register(reg_for_width(
        extend_reg(modrm.reg, vex.rex.r),
        width_bits,
        vex.rex.present,
    ));
    let (src, consumed) = parse_vector_rm_operand(bytes, modrm_offset, vex)?;
    let kind = if matches!(src, Operand::Memory(_)) {
        InstructionKind::Load
    } else {
        InstructionKind::Move
    };
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        if width_bits == 64 { "vmovq" } else { "vmovd" },
        vec![dst, src],
        kind,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_vex_packed_shift_imm(bytes: &[u8], address: u64, vex: Vex) -> Result<Instruction> {
    let modrm_offset = vex.opcode_offset + 1;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let mnemonic = match modrm.reg {
        0x2 => "vpsrlq",
        0x6 => "vpsllq",
        _ => return Ok(unknown(bytes[0], address)),
    };
    let dst = Operand::Register(vector_reg(vex.vvvv, vex));
    let (src, consumed_without_imm) = parse_vector_rm_operand(bytes, modrm_offset, vex)?;
    let size = consumed_without_imm + 1;
    let imm = i64::from(read_u8(bytes, consumed_without_imm)?);
    Ok(base(
        bytes[..size].to_vec(),
        address,
        mnemonic,
        vec![dst, src, Operand::Immediate(imm)],
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_vex_binary(
    bytes: &[u8],
    address: u64,
    vex: Vex,
    mnemonic: &str,
    kind: InstructionKind,
) -> Result<Instruction> {
    let modrm_offset = vex.opcode_offset + 1;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let dst = Operand::Register(vector_reg(extend_reg(modrm.reg, vex.rex.r), vex));
    let (src, consumed) = parse_vector_rm_operand(bytes, modrm_offset, vex)?;
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        mnemonic,
        vec![dst, src],
        kind,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_vinsertf128(bytes: &[u8], address: u64, vex: Vex) -> Result<Instruction> {
    let modrm_offset = vex.opcode_offset + 1;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let dst = Operand::Register(ymm(extend_reg(modrm.reg, vex.rex.r)));
    let src1 = Operand::Register(ymm(vex.vvvv));
    let source_vex = Vex {
        l_256: false,
        ..vex
    };
    let (src2, consumed_without_imm) = parse_vector_rm_operand(bytes, modrm_offset, source_vex)?;
    let size = consumed_without_imm + 1;
    let imm = i64::from(read_u8(bytes, consumed_without_imm)?);
    Ok(base(
        bytes[..size].to_vec(),
        address,
        "vinsertf128",
        vec![dst, src1, src2, Operand::Immediate(imm)],
        InstructionKind::Move,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_vex_ternary_binary(
    bytes: &[u8],
    address: u64,
    vex: Vex,
    mnemonic: &str,
    kind: InstructionKind,
) -> Result<Instruction> {
    let modrm_offset = vex.opcode_offset + 1;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let dst = Operand::Register(vector_reg(extend_reg(modrm.reg, vex.rex.r), vex));
    let src1 = Operand::Register(vector_reg(vex.vvvv, vex));
    let (src2, consumed) = parse_vector_rm_operand(bytes, modrm_offset, vex)?;
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        mnemonic,
        vec![dst, src1, src2],
        kind,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_cmovcc(
    bytes: &[u8],
    address: u64,
    prefixes: Prefixes,
    opcode: u8,
) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 2;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let width_bits = default_operand_width(prefixes);
    let dst = Operand::Register(reg_for_width(
        extend_reg(modrm.reg, prefixes.rex.r),
        width_bits,
        prefixes.rex.present,
    ));
    let (src, consumed) = parse_rm_operand(bytes, modrm_offset, prefixes.rex, width_bits)?;
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        mnemonic_for_cmovcc(opcode),
        vec![dst, src],
        InstructionKind::Move,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_bit_test_reg(
    bytes: &[u8],
    address: u64,
    prefixes: Prefixes,
    mnemonic: &str,
    kind: InstructionKind,
) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 2;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let width_bits = default_operand_width(prefixes);
    let reg = Operand::Register(reg_for_width(
        extend_reg(modrm.reg, prefixes.rex.r),
        width_bits,
        prefixes.rex.present,
    ));
    let (rm, consumed) = parse_rm_operand(bytes, modrm_offset, prefixes.rex, width_bits)?;
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        mnemonic,
        vec![rm, reg],
        kind,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_bit_test_imm(bytes: &[u8], address: u64, prefixes: Prefixes) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 2;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let (mnemonic, kind) = match modrm.reg {
        0b100 => ("bt", InstructionKind::Compare),
        0b101 => ("bts", InstructionKind::Logical),
        0b110 => ("btr", InstructionKind::Logical),
        0b111 => ("btc", InstructionKind::Logical),
        _ => return Ok(unknown(bytes[prefixes.opcode_offset], address)),
    };
    let width_bits = default_operand_width(prefixes);
    let (rm, consumed_without_imm) =
        parse_rm_operand(bytes, modrm_offset, prefixes.rex, width_bits)?;
    let imm = i64::from(read_u8(bytes, consumed_without_imm)?);
    let consumed = consumed_without_imm + 1;
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

fn decode_movzx_word(bytes: &[u8], address: u64, prefixes: Prefixes) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 2;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let dst = Operand::Register(reg_for_width(
        extend_reg(modrm.reg, prefixes.rex.r),
        default_operand_width(prefixes),
        prefixes.rex.present,
    ));
    let (src, consumed) = if modrm.mode == 0b11 {
        (
            Operand::Register(reg16(extend_reg(modrm.rm, prefixes.rex.b))),
            modrm_offset + 1,
        )
    } else {
        parse_rm_operand(bytes, modrm_offset, prefixes.rex, 16)?
    };
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        "movzx",
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

fn decode_imul_rm(bytes: &[u8], address: u64, prefixes: Prefixes) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 2;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let width_bits = default_operand_width(prefixes);
    let dst = Operand::Register(reg_for_width(
        extend_reg(modrm.reg, prefixes.rex.r),
        width_bits,
        prefixes.rex.present,
    ));
    let (src, consumed) = parse_rm_operand(bytes, modrm_offset, prefixes.rex, width_bits)?;
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        "imul",
        vec![dst, src],
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_imul_imm(
    bytes: &[u8],
    address: u64,
    prefixes: Prefixes,
    imm_width_bits: u16,
) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 1;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let width_bits = default_operand_width(prefixes);
    let dst = Operand::Register(reg_for_width(
        extend_reg(modrm.reg, prefixes.rex.r),
        width_bits,
        prefixes.rex.present,
    ));
    let (src, consumed_without_imm) =
        parse_rm_operand(bytes, modrm_offset, prefixes.rex, width_bits)?;
    let (imm, consumed) = if imm_width_bits == 8 {
        (
            i64::from(read_i8(bytes, consumed_without_imm)?),
            consumed_without_imm + 1,
        )
    } else {
        (
            i64::from(read_i32(bytes, consumed_without_imm)?),
            consumed_without_imm + 4,
        )
    };
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        "imul",
        vec![dst, src, Operand::Immediate(imm)],
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_cmpxchg(
    bytes: &[u8],
    address: u64,
    prefixes: Prefixes,
    width_bits: u16,
) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 2;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let reg = Operand::Register(reg_for_width(
        extend_reg(modrm.reg, prefixes.rex.r),
        width_bits,
        prefixes.rex.present,
    ));
    let (rm, consumed) = parse_rm_operand(bytes, modrm_offset, prefixes.rex, width_bits)?;
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        "cmpxchg",
        vec![rm, reg],
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_xadd(
    bytes: &[u8],
    address: u64,
    prefixes: Prefixes,
    width_bits: u16,
) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 2;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let reg = Operand::Register(reg_for_width(
        extend_reg(modrm.reg, prefixes.rex.r),
        width_bits,
        prefixes.rex.present,
    ));
    let (rm, consumed) = parse_rm_operand(bytes, modrm_offset, prefixes.rex, width_bits)?;
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        "xadd",
        vec![rm, reg],
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_bsf(bytes: &[u8], address: u64, prefixes: Prefixes) -> Result<Instruction> {
    decode_bit_scan(bytes, address, prefixes, "bsf")
}

fn decode_bit_scan(
    bytes: &[u8],
    address: u64,
    prefixes: Prefixes,
    mnemonic: &str,
) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 2;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let width_bits = default_operand_width(prefixes);
    let dst = Operand::Register(reg_for_width(
        extend_reg(modrm.reg, prefixes.rex.r),
        width_bits,
        prefixes.rex.present,
    ));
    let (src, consumed) = parse_rm_operand(bytes, modrm_offset, prefixes.rex, width_bits)?;
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        mnemonic,
        vec![dst, src],
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_bswap(bytes: &[u8], address: u64, prefixes: Prefixes, opcode: u8) -> Result<Instruction> {
    let reg = extend_reg(opcode - 0xc8, prefixes.rex.b);
    let width_bits = if prefixes.rex.w { 64 } else { 32 };
    Ok(base(
        bytes[..prefixes.opcode_offset + 2].to_vec(),
        address,
        "bswap",
        vec![Operand::Register(reg_for_width(
            reg,
            width_bits,
            prefixes.rex.present,
        ))],
        InstructionKind::Move,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_sse_move(
    bytes: &[u8],
    address: u64,
    prefixes: Prefixes,
    opcode: u8,
) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 2;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let reg = Operand::Register(xmm(extend_reg(modrm.reg, prefixes.rex.r)));
    let (rm, consumed) = parse_xmm_rm_operand(bytes, modrm_offset, prefixes.rex)?;
    let is_store = matches!(opcode, 0x11 | 0x29);
    let operands = if is_store {
        vec![rm.clone(), reg]
    } else {
        vec![reg, rm.clone()]
    };
    let mnemonic = if matches!(opcode, 0x10 | 0x11) {
        "movups"
    } else {
        "movaps"
    };
    let kind = match (is_store, matches!(rm, Operand::Memory(_))) {
        (true, true) => InstructionKind::Store,
        (false, true) => InstructionKind::Load,
        _ => InstructionKind::Move,
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

fn decode_movd_movq(bytes: &[u8], address: u64, prefixes: Prefixes) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 2;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let width_bits = if prefixes.rex.w { 64 } else { 32 };
    let src = if prefixes.operand_size_override {
        Operand::Register(xmm(extend_reg(modrm.reg, prefixes.rex.r)))
    } else {
        Operand::Register(mm(extend_reg(modrm.reg, prefixes.rex.r)))
    };
    let (dst, consumed) = parse_rm_operand(bytes, modrm_offset, prefixes.rex, width_bits)?;
    let kind = if matches!(dst, Operand::Memory(_)) {
        InstructionKind::Store
    } else {
        InstructionKind::Move
    };
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        if width_bits == 64 { "movq" } else { "movd" },
        vec![dst, src],
        kind,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_movd_movq_to_vector(
    bytes: &[u8],
    address: u64,
    prefixes: Prefixes,
) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 2;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let width_bits = if prefixes.rex.w { 64 } else { 32 };
    let dst = if prefixes.operand_size_override {
        Operand::Register(xmm(extend_reg(modrm.reg, prefixes.rex.r)))
    } else {
        Operand::Register(mm(extend_reg(modrm.reg, prefixes.rex.r)))
    };
    let (src, consumed) = parse_rm_operand(bytes, modrm_offset, prefixes.rex, width_bits)?;
    let kind = if matches!(src, Operand::Memory(_)) {
        InstructionKind::Load
    } else {
        InstructionKind::Move
    };
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        if width_bits == 64 { "movq" } else { "movd" },
        vec![dst, src],
        kind,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_pcmpeqb(bytes: &[u8], address: u64, prefixes: Prefixes) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 2;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let (dst, src, consumed) = if prefixes.operand_size_override {
        let dst = Operand::Register(xmm(extend_reg(modrm.reg, prefixes.rex.r)));
        let (src, consumed) = parse_xmm_rm_operand(bytes, modrm_offset, prefixes.rex)?;
        (dst, src, consumed)
    } else {
        let dst = Operand::Register(mm(extend_reg(modrm.reg, prefixes.rex.r)));
        let (src, consumed) = parse_mmx_rm_operand(bytes, modrm_offset, prefixes.rex)?;
        (dst, src, consumed)
    };
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        "pcmpeqb",
        vec![dst, src],
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_mmx_move(
    bytes: &[u8],
    address: u64,
    prefixes: Prefixes,
    opcode: u8,
) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 2;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let reg = Operand::Register(mm(extend_reg(modrm.reg, prefixes.rex.r)));
    let (rm, consumed) = parse_mmx_rm_operand(bytes, modrm_offset, prefixes.rex)?;
    let is_store = opcode == 0x7f;
    let operands = if is_store {
        vec![rm.clone(), reg]
    } else {
        vec![reg, rm.clone()]
    };
    let kind = match (is_store, matches!(rm, Operand::Memory(_))) {
        (true, true) => InstructionKind::Store,
        (false, true) => InstructionKind::Load,
        _ => InstructionKind::Move,
    };
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        "movq",
        operands,
        kind,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_cvtps2pi(bytes: &[u8], address: u64, prefixes: Prefixes) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 2;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let dst = Operand::Register(mm(extend_reg(modrm.reg, prefixes.rex.r)));
    let (src, consumed) = if modrm.mode == 0b11 {
        (
            Operand::Register(xmm(extend_reg(modrm.rm, prefixes.rex.b))),
            modrm_offset + 1,
        )
    } else {
        parse_rm_operand(bytes, modrm_offset, prefixes.rex, 64)?
    };
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        "cvtps2pi",
        vec![dst, src],
        InstructionKind::Arithmetic,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_mmx_opcode(
    bytes: &[u8],
    address: u64,
    prefixes: Prefixes,
    opcode: u8,
) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 2;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    if opcode == 0xd7 {
        let dst = Operand::Register(reg32(extend_reg(modrm.reg, prefixes.rex.r)));
        let (src, consumed) = parse_mmx_rm_operand(bytes, modrm_offset, prefixes.rex)?;
        return Ok(base(
            bytes[..consumed].to_vec(),
            address,
            "pmovmskb",
            vec![dst, src],
            InstructionKind::Move,
            FlowKind::Fallthrough,
            None,
        ));
    }

    let (reg, rm, consumed) = if prefixes.operand_size_override {
        let reg = Operand::Register(xmm(extend_reg(modrm.reg, prefixes.rex.r)));
        let (rm, consumed) = parse_xmm_rm_operand(bytes, modrm_offset, prefixes.rex)?;
        (reg, rm, consumed)
    } else {
        let reg = Operand::Register(mm(extend_reg(modrm.reg, prefixes.rex.r)));
        let (rm, consumed) = parse_mmx_rm_operand(bytes, modrm_offset, prefixes.rex)?;
        (reg, rm, consumed)
    };
    let (mnemonic, kind) = match opcode {
        0x60 => ("punpcklbw", InstructionKind::Move),
        0x64 => ("pcmpgtb", InstructionKind::Compare),
        0xdb => ("pand", InstructionKind::Logical),
        0xe0 => ("pavgb", InstructionKind::Arithmetic),
        0xeb => ("por", InstructionKind::Logical),
        0xef => ("pxor", InstructionKind::Logical),
        0xf1 => ("psllw", InstructionKind::Logical),
        0xf5 => ("pmaddwd", InstructionKind::Arithmetic),
        0xfa => ("psubd", InstructionKind::Arithmetic),
        0xfb => ("psubq", InstructionKind::Arithmetic),
        0xfd => ("paddw", InstructionKind::Arithmetic),
        _ => unreachable!("opcode filtered by caller"),
    };
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        mnemonic,
        vec![reg, rm],
        kind,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_packed_shuffle(bytes: &[u8], address: u64, prefixes: Prefixes) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 2;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let (mnemonic, dst, src, consumed_without_imm) = match prefixes.repeat_prefix {
        Some(0xf2) if prefixes.operand_size_override => {
            let dst = Operand::Register(xmm(extend_reg(modrm.reg, prefixes.rex.r)));
            let (src, consumed) = parse_xmm_rm_operand(bytes, modrm_offset, prefixes.rex)?;
            ("pshuflw", dst, src, consumed)
        }
        Some(0xf3) if prefixes.operand_size_override => {
            let dst = Operand::Register(xmm(extend_reg(modrm.reg, prefixes.rex.r)));
            let (src, consumed) = parse_xmm_rm_operand(bytes, modrm_offset, prefixes.rex)?;
            ("pshufhw", dst, src, consumed)
        }
        _ if prefixes.operand_size_override => {
            let dst = Operand::Register(xmm(extend_reg(modrm.reg, prefixes.rex.r)));
            let (src, consumed) = parse_xmm_rm_operand(bytes, modrm_offset, prefixes.rex)?;
            ("pshufd", dst, src, consumed)
        }
        _ => {
            let dst = Operand::Register(mm(extend_reg(modrm.reg, prefixes.rex.r)));
            let (src, consumed) = parse_mmx_rm_operand(bytes, modrm_offset, prefixes.rex)?;
            ("pshufw", dst, src, consumed)
        }
    };
    let imm = i64::from(read_u8(bytes, consumed_without_imm)?);
    let consumed = consumed_without_imm + 1;
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        mnemonic,
        vec![dst, src, Operand::Immediate(imm)],
        InstructionKind::Move,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_packed_shift_imm(bytes: &[u8], address: u64, prefixes: Prefixes) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 2;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    if modrm.mode != 0b11 {
        return Ok(unknown(bytes[prefixes.opcode_offset], address));
    }

    let imm = i64::from(read_u8(bytes, modrm_offset + 1)?);
    let (mnemonic, dst) = match (prefixes.operand_size_override, modrm.reg) {
        (false, 0b010) => (
            "psrlq",
            Operand::Register(mm(extend_reg(modrm.rm, prefixes.rex.b))),
        ),
        (false, 0b110) => (
            "psllq",
            Operand::Register(mm(extend_reg(modrm.rm, prefixes.rex.b))),
        ),
        (true, 0b010) => (
            "psrlq",
            Operand::Register(xmm(extend_reg(modrm.rm, prefixes.rex.b))),
        ),
        (true, 0b011) => (
            "psrldq",
            Operand::Register(xmm(extend_reg(modrm.rm, prefixes.rex.b))),
        ),
        (true, 0b110) => (
            "psllq",
            Operand::Register(xmm(extend_reg(modrm.rm, prefixes.rex.b))),
        ),
        (true, 0b111) => (
            "pslldq",
            Operand::Register(xmm(extend_reg(modrm.rm, prefixes.rex.b))),
        ),
        _ => return Ok(unknown(bytes[prefixes.opcode_offset], address)),
    };
    let consumed = modrm_offset + 2;
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        mnemonic,
        vec![dst, Operand::Immediate(imm)],
        InstructionKind::Logical,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_sse_binary(
    bytes: &[u8],
    address: u64,
    prefixes: Prefixes,
    mnemonic: &str,
    kind: InstructionKind,
) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 2;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let reg = Operand::Register(xmm(extend_reg(modrm.reg, prefixes.rex.r)));
    let (rm, consumed) = parse_xmm_rm_operand(bytes, modrm_offset, prefixes.rex)?;
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        mnemonic,
        vec![reg, rm],
        kind,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_sse_compare_unordered(
    bytes: &[u8],
    address: u64,
    prefixes: Prefixes,
    opcode: u8,
) -> Result<Instruction> {
    let mnemonic = match (opcode, prefixes.operand_size_override) {
        (0x2e, true) => "ucomisd",
        (0x2e, false) => "ucomiss",
        (0x2f, true) => "comisd",
        _ => "comiss",
    };
    decode_sse_binary(bytes, address, prefixes, mnemonic, InstructionKind::Compare)
}

fn decode_sse_compare(bytes: &[u8], address: u64, prefixes: Prefixes) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 2;
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    let reg = Operand::Register(xmm(extend_reg(modrm.reg, prefixes.rex.r)));
    let (rm, consumed_without_imm) = parse_xmm_rm_operand(bytes, modrm_offset, prefixes.rex)?;
    let imm = i64::from(read_u8(bytes, consumed_without_imm)?);
    let consumed = consumed_without_imm + 1;
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        "cmpps",
        vec![reg, rm, Operand::Immediate(imm)],
        InstructionKind::Compare,
        FlowKind::Fallthrough,
        None,
    ))
}

fn decode_setcc(bytes: &[u8], address: u64, prefixes: Prefixes, opcode: u8) -> Result<Instruction> {
    let modrm_offset = prefixes.opcode_offset + 2;
    require_len(bytes, modrm_offset + 1)?;
    let (rm, consumed) = parse_rm_operand(bytes, modrm_offset, prefixes.rex, 8)?;
    let kind = if matches!(rm, Operand::Memory(_)) {
        InstructionKind::Store
    } else {
        InstructionKind::Move
    };
    Ok(base(
        bytes[..consumed].to_vec(),
        address,
        mnemonic_for_setcc(opcode),
        vec![rm],
        kind,
        FlowKind::Fallthrough,
        None,
    ))
}

fn parse_prefixes(bytes: &[u8]) -> Result<Prefixes> {
    require_len(bytes, 1)?;
    let mut offset = 0;
    let mut rex = Rex::default();
    let mut operand_size_override = false;
    let mut repeat_prefix = None;
    while offset < bytes.len() {
        let byte = bytes[offset];
        if byte == 0x66 {
            operand_size_override = true;
            offset += 1;
        } else if matches!(byte, 0xf2 | 0xf3) {
            repeat_prefix = Some(byte);
            offset += 1;
        } else if matches!(byte, 0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x67 | 0xf0) {
            offset += 1;
        } else if (0x40..=0x4f).contains(&byte) {
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
        operand_size_override,
        repeat_prefix,
        opcode_offset: offset,
    })
}

fn parse_vex(bytes: &[u8], offset: usize) -> Result<Vex> {
    require_len(bytes, offset + 2)?;
    if bytes[offset] == 0xc5 {
        let byte = bytes[offset + 1];
        return Ok(Vex {
            rex: Rex {
                present: false,
                w: false,
                r: byte & 0x80 == 0,
                x: false,
                b: false,
            },
            vvvv: (!((byte >> 3) & 0x0f)) & 0x0f,
            map: 0x01,
            pp: byte & 0x03,
            l_256: byte & 0x04 != 0,
            opcode_offset: offset + 2,
        });
    }

    require_len(bytes, offset + 3)?;
    let byte2 = bytes[offset + 1];
    let byte3 = bytes[offset + 2];
    Ok(Vex {
        rex: Rex {
            present: false,
            w: byte3 & 0x80 != 0,
            r: byte2 & 0x80 == 0,
            x: byte2 & 0x40 == 0,
            b: byte2 & 0x20 == 0,
        },
        vvvv: (!((byte3 >> 3) & 0x0f)) & 0x0f,
        map: byte2 & 0x1f,
        pp: byte3 & 0x03,
        l_256: byte3 & 0x04 != 0,
        opcode_offset: offset + 3,
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

fn read_u8(bytes: &[u8], offset: usize) -> Result<u8> {
    require_len(bytes, offset + 1)?;
    Ok(bytes[offset])
}

fn read_i16(bytes: &[u8], offset: usize) -> Result<i16> {
    require_len(bytes, offset + 2)?;
    Ok(i16::from_le_bytes([bytes[offset], bytes[offset + 1]]))
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    require_len(bytes, offset + 2)?;
    Ok(u16::from_le_bytes([bytes[offset], bytes[offset + 1]]))
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

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    require_len(bytes, offset + 4)?;
    Ok(u32::from_le_bytes([
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
        let reg = reg_for_width(extend_reg(modrm.rm, rex.b), width_bits, rex.present);
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

fn parse_xmm_rm_operand(bytes: &[u8], modrm_offset: usize, rex: Rex) -> Result<(Operand, usize)> {
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    if modrm.mode == 0b11 {
        return Ok((
            Operand::Register(xmm(extend_reg(modrm.rm, rex.b))),
            modrm_offset + 1,
        ));
    }
    parse_rm_operand(bytes, modrm_offset, rex, 128)
}

fn parse_vector_rm_operand(
    bytes: &[u8],
    modrm_offset: usize,
    vex: Vex,
) -> Result<(Operand, usize)> {
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    if modrm.mode == 0b11 {
        return Ok((
            Operand::Register(vector_reg(extend_reg(modrm.rm, vex.rex.b), vex)),
            modrm_offset + 1,
        ));
    }
    parse_rm_operand(bytes, modrm_offset, vex.rex, vector_width_bits(vex))
}

fn parse_mmx_rm_operand(bytes: &[u8], modrm_offset: usize, rex: Rex) -> Result<(Operand, usize)> {
    require_len(bytes, modrm_offset + 1)?;
    let modrm = parse_modrm(bytes[modrm_offset]);
    if modrm.mode == 0b11 {
        return Ok((
            Operand::Register(mm(extend_reg(modrm.rm, rex.b))),
            modrm_offset + 1,
        ));
    }
    parse_rm_operand(bytes, modrm_offset, rex, 64)
}

fn rel_target(address: u64, size: usize, displacement: i64) -> u64 {
    address
        .wrapping_add(size as u64)
        .wrapping_add_signed(displacement)
}

fn absolute_target(target: u64) -> Vec<Operand> {
    vec![Operand::AbsoluteAddress(target)]
}

fn reg_for_width(index: u8, width_bits: u16, rex_present: bool) -> crate::model::Register {
    match width_bits {
        8 => reg8(index, rex_present),
        16 => reg16(index),
        32 => reg32(index),
        _ => reg64(index),
    }
}

fn vector_reg(index: u8, vex: Vex) -> crate::model::Register {
    if vex.l_256 {
        ymm(index)
    } else {
        xmm(index)
    }
}

fn vector_width_bits(vex: Vex) -> u16 {
    if vex.l_256 {
        256
    } else {
        128
    }
}

fn default_operand_width(prefixes: Prefixes) -> u16 {
    if prefixes.rex.w {
        64
    } else if prefixes.operand_size_override {
        16
    } else {
        32
    }
}

fn mnemonic_for_acc_sign_extend(prefixes: Prefixes) -> &'static str {
    if prefixes.rex.w {
        "cdqe"
    } else if prefixes.operand_size_override {
        "cbw"
    } else {
        "cwde"
    }
}

fn mnemonic_for_dx_acc_sign_extend(prefixes: Prefixes) -> &'static str {
    if prefixes.rex.w {
        "cqo"
    } else if prefixes.operand_size_override {
        "cwd"
    } else {
        "cdq"
    }
}

fn mnemonic_for_string_sized(stem: &str, width_bits: u16) -> &'static str {
    match (stem, width_bits) {
        ("movs", 16) => "movsw",
        ("movs", 64) => "movsq",
        ("movs", _) => "movsd",
        ("cmps", 16) => "cmpsw",
        ("cmps", 64) => "cmpsq",
        ("cmps", _) => "cmpsd",
        ("stos", 16) => "stosw",
        ("stos", 64) => "stosq",
        ("stos", _) => "stosd",
        ("lods", 16) => "lodsw",
        ("lods", 64) => "lodsq",
        ("lods", _) => "lodsd",
        ("scas", 16) => "scasw",
        ("scas", 64) => "scasq",
        ("scas", _) => "scasd",
        _ => unreachable!("unknown string instruction stem"),
    }
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

fn mnemonic_for_setcc(opcode: u8) -> &'static str {
    match opcode & 0x0f {
        0x0 => "seto",
        0x1 => "setno",
        0x2 => "setb",
        0x3 => "setae",
        0x4 => "sete",
        0x5 => "setne",
        0x6 => "setbe",
        0x7 => "seta",
        0x8 => "sets",
        0x9 => "setns",
        0xa => "setp",
        0xb => "setnp",
        0xc => "setl",
        0xd => "setge",
        0xe => "setle",
        _ => "setg",
    }
}

fn mnemonic_for_cmovcc(opcode: u8) -> &'static str {
    match opcode & 0x0f {
        0x0 => "cmovo",
        0x1 => "cmovno",
        0x2 => "cmovb",
        0x3 => "cmovae",
        0x4 => "cmove",
        0x5 => "cmovne",
        0x6 => "cmovbe",
        0x7 => "cmova",
        0x8 => "cmovs",
        0x9 => "cmovns",
        0xa => "cmovp",
        0xb => "cmovnp",
        0xc => "cmovl",
        0xd => "cmovge",
        0xe => "cmovle",
        _ => "cmovg",
    }
}

fn mnemonic_for_sse_binary(opcode: u8, prefixes: Prefixes) -> &'static str {
    match opcode {
        0x54 if prefixes.operand_size_override => "andpd",
        0x54 => "andps",
        0x56 if prefixes.operand_size_override => "orpd",
        0x56 => "orps",
        0x58 if prefixes.repeat_prefix == Some(0xf2) => "addsd",
        0x58 if prefixes.repeat_prefix == Some(0xf3) => "addss",
        0x58 if prefixes.operand_size_override => "addpd",
        0x58 => "addps",
        0x5c if prefixes.repeat_prefix == Some(0xf2) => "subsd",
        0x5c if prefixes.repeat_prefix == Some(0xf3) => "subss",
        0x5c if prefixes.operand_size_override => "subpd",
        0x5c => "subps",
        0x5e if prefixes.repeat_prefix == Some(0xf2) => "divsd",
        0x5e if prefixes.repeat_prefix == Some(0xf3) => "divss",
        0x5e if prefixes.operand_size_override => "divpd",
        _ => "divps",
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
