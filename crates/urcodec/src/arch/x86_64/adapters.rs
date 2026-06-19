use crate::{
    arch::x86_64::registers::{mm, reg16, reg32, reg64, reg8, xmm, ymm},
    error::{DecodeError, EncodeError},
    model::{MemoryOperand, Operand, Register},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedModrmMemory {
    pub rex_x: u8,
    pub rex_b: u8,
    pub mod_bits: u8,
    pub rm_low_bits: u8,
    pub sib: Option<u8>,
    pub displacement: Vec<u8>,
}

pub fn format_operands(operands: &[Operand]) -> String {
    operands
        .iter()
        .map(format_operand)
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn format_operand(operand: &Operand) -> String {
    match operand {
        Operand::Register(register) => register.name.clone(),
        Operand::Immediate(value) => format_immediate(*value),
        Operand::AbsoluteAddress(value) => format_address(*value),
        Operand::Condition(condition) => condition.clone(),
        Operand::ShiftedRegister(shifted) => shifted.register.name.clone(),
        Operand::Memory(memory) => render_memory(memory),
    }
}

pub fn format_immediate(value: i64) -> String {
    if value < 0 {
        format!("-0x{:x}", value.unsigned_abs())
    } else {
        format!("0x{:x}", value as u64)
    }
}

pub fn format_address(value: u64) -> String {
    format!("0x{value:x}")
}

pub fn parse_target_text(text: &str) -> Option<u64> {
    u64::from_str_radix(text.trim().strip_prefix("0x")?, 16).ok()
}

pub fn parse_immediate(text: &str) -> Option<i64> {
    let trimmed = text.trim();
    if let Some(hex) = trimmed.strip_prefix("-0x") {
        let value = u64::from_str_radix(hex, 16).ok()?;
        i64::try_from(value).ok().map(|value| -value)
    } else if let Some(hex) = trimmed.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok().map(|value| value as i64)
    } else {
        trimmed.parse().ok()
    }
}

pub fn parse_r64_register(name: &str) -> Option<u8> {
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

pub fn parse_r32_register(name: &str) -> Option<u8> {
    Some(match name {
        "eax" => 0,
        "ecx" => 1,
        "edx" => 2,
        "ebx" => 3,
        "esp" => 4,
        "ebp" => 5,
        "esi" => 6,
        "edi" => 7,
        "r8d" => 8,
        "r9d" => 9,
        "r10d" => 10,
        "r11d" => 11,
        "r12d" => 12,
        "r13d" => 13,
        "r14d" => 14,
        "r15d" => 15,
        _ => return None,
    })
}

pub fn parse_r16_register(name: &str) -> Option<u8> {
    Some(match name {
        "ax" => 0,
        "cx" => 1,
        "dx" => 2,
        "bx" => 3,
        "sp" => 4,
        "bp" => 5,
        "si" => 6,
        "di" => 7,
        "r8w" => 8,
        "r9w" => 9,
        "r10w" => 10,
        "r11w" => 11,
        "r12w" => 12,
        "r13w" => 13,
        "r14w" => 14,
        "r15w" => 15,
        _ => return None,
    })
}

pub fn parse_r8_register(name: &str) -> Option<u8> {
    Some(match name {
        "al" => 0,
        "cl" => 1,
        "dl" => 2,
        "bl" => 3,
        "ah" => 4,
        "ch" => 5,
        "dh" => 6,
        "bh" => 7,
        "spl" => 4,
        "bpl" => 5,
        "sil" => 6,
        "dil" => 7,
        "r8b" => 8,
        "r9b" => 9,
        "r10b" => 10,
        "r11b" => 11,
        "r12b" => 12,
        "r13b" => 13,
        "r14b" => 14,
        "r15b" => 15,
        _ => return None,
    })
}

pub fn parse_mm_register(name: &str) -> Option<u8> {
    name.strip_prefix("mm")?
        .parse::<u8>()
        .ok()
        .filter(|index| *index < 8)
}

pub fn parse_xmm_register(name: &str) -> Option<u8> {
    name.strip_prefix("xmm")?
        .parse::<u8>()
        .ok()
        .filter(|index| *index < 16)
}

pub fn parse_ymm_register(name: &str) -> Option<u8> {
    name.strip_prefix("ymm")?
        .parse::<u8>()
        .ok()
        .filter(|index| *index < 16)
}

pub fn r64_register(index: u32) -> Register {
    reg64(index as u8)
}

pub fn r32_register(index: u32) -> Register {
    reg32(index as u8)
}

pub fn r16_register(index: u32) -> Register {
    reg16(index as u8)
}

pub fn r8_register(index: u32) -> Register {
    reg8(index as u8, false)
}

pub fn mm_register(index: u32) -> Register {
    mm(index as u8)
}

pub fn xmm_register(index: u32) -> Register {
    xmm(index as u8)
}

pub fn ymm_register(index: u32) -> Register {
    ymm(index as u8)
}

pub fn modrm_operand_end(bytes: &[u8], modrm_offset: usize) -> Result<usize, DecodeError> {
    let modrm = *bytes
        .get(modrm_offset)
        .ok_or(DecodeError::TruncatedInstruction {
            expected: modrm_offset + 1,
            actual: bytes.len(),
        })?;
    let mode = modrm >> 6;
    let rm = modrm & 0x07;
    let mut consumed = modrm_offset + 1;

    if mode != 0b11 && rm == 0b100 {
        let sib = *bytes
            .get(consumed)
            .ok_or(DecodeError::TruncatedInstruction {
                expected: consumed + 1,
                actual: bytes.len(),
            })?;
        consumed += 1;
        let sib_base = sib & 0x07;
        if mode == 0 && sib_base == 0b101 {
            consumed += require_len(bytes, consumed, 4)?;
        }
    } else if mode == 0 && rm == 0b101 {
        consumed += require_len(bytes, consumed, 4)?;
    }

    match mode {
        0b01 => consumed += require_len(bytes, consumed, 1)?,
        0b10 => consumed += require_len(bytes, consumed, 4)?,
        _ => {}
    }

    Ok(consumed)
}

pub fn decode_modrm_memory(
    bytes: &[u8],
    modrm_offset: usize,
    width_bits: u16,
) -> Result<MemoryOperand, DecodeError> {
    let modrm = *bytes
        .get(modrm_offset)
        .ok_or(DecodeError::TruncatedInstruction {
            expected: modrm_offset + 1,
            actual: bytes.len(),
        })?;
    let mode = modrm >> 6;
    if mode == 0b11 {
        return Err(DecodeError::UnsupportedTarget);
    }

    let rex = extension_prefix(bytes, modrm_offset);
    let mut consumed = modrm_offset + 1;
    let mut base = None;
    let mut index = None;
    let mut scale = 1u8;
    let mut offset = 0i64;
    let mut relative = false;

    if (modrm & 0x07) == 0b100 {
        let sib = *bytes
            .get(consumed)
            .ok_or(DecodeError::TruncatedInstruction {
                expected: consumed + 1,
                actual: bytes.len(),
            })?;
        consumed += 1;
        scale = 1u8 << (sib >> 6);
        let sib_index = (sib >> 3) & 0x07;
        let sib_base = sib & 0x07;
        if sib_index != 0b100 || rex.x == 1 {
            index = Some(reg64(extend_reg(sib_index, rex.x)));
        }
        if mode == 0 && sib_base == 0b101 {
            offset = read_i32_as_i64(bytes, consumed)?;
            consumed += 4;
        } else {
            base = Some(reg64(extend_reg(sib_base, rex.b)));
        }
    } else if mode == 0 && (modrm & 0x07) == 0b101 {
        relative = true;
        offset = read_i32_as_i64(bytes, consumed)?;
        consumed += 4;
    } else {
        base = Some(reg64(extend_reg(modrm & 0x07, rex.b)));
    }

    match mode {
        0b00 => {}
        0b01 => {
            offset = i64::from(read_i8(bytes, consumed)?);
        }
        0b10 => {
            offset = read_i32_as_i64(bytes, consumed)?;
        }
        _ => unreachable!(),
    }

    let mut memory = if relative {
        MemoryOperand::rip_relative(offset, Some(width_bits))
    } else {
        MemoryOperand::indexed(base, index, scale, offset, Some(width_bits))
    };
    memory.relative = relative;
    Ok(memory)
}

pub fn encode_modrm_memory(memory: &MemoryOperand) -> Result<EncodedModrmMemory, EncodeError> {
    if memory.writeback || memory.post_index {
        return Err(EncodeError::OperandMismatch(
            "x86 memory operand".to_string(),
        ));
    }
    if memory.relative {
        if memory.index.is_some() {
            return Err(EncodeError::OperandMismatch(
                "x86 memory operand".to_string(),
            ));
        }
        let base_ok = memory
            .base
            .as_ref()
            .is_some_and(|register| register.name == "rip");
        if !base_ok {
            return Err(EncodeError::OperandMismatch(
                "x86 memory operand".to_string(),
            ));
        }
        let disp = i32::try_from(memory.offset)
            .map_err(|_| EncodeError::OperandMismatch("x86 memory operand".to_string()))?;
        return Ok(EncodedModrmMemory {
            rex_x: 0,
            rex_b: 0,
            mod_bits: 0b00,
            rm_low_bits: 0b101,
            sib: None,
            displacement: disp.to_le_bytes().to_vec(),
        });
    }

    let base = memory
        .base
        .as_ref()
        .ok_or_else(|| EncodeError::OperandMismatch("x86 memory operand".to_string()))?;
    let base_index = parse_r64_register(&base.name)
        .ok_or_else(|| EncodeError::OperandMismatch("x86 memory operand".to_string()))?;
    let base_low_bits = base_index & 0x07;
    let rex_b = u8::from(base_index >= 8);

    let (rex_x, index_low_bits) = if let Some(index) = &memory.index {
        let index_value = parse_r64_register(&index.name)
            .ok_or_else(|| EncodeError::OperandMismatch("x86 memory operand".to_string()))?;
        if index_value == 4 {
            return Err(EncodeError::OperandMismatch(
                "x86 memory operand".to_string(),
            ));
        }
        (u8::from(index_value >= 8), index_value & 0x07)
    } else {
        (0, 0b100)
    };

    let use_sib = memory.index.is_some() || base_low_bits == 0b100;
    let requires_displacement = base_low_bits == 0b101;
    let displacement = encode_displacement(memory.offset, requires_displacement)?;
    let mod_bits = displacement_mod_bits(memory.offset, requires_displacement)?;
    let rm_low_bits = if use_sib { 0b100 } else { base_low_bits };
    let sib = use_sib.then(|| {
        let scale_bits = match memory.scale {
            1 => 0,
            2 => 1,
            4 => 2,
            8 => 3,
            _ => unreachable!(),
        };
        (scale_bits << 6) | (index_low_bits << 3) | base_low_bits
    });

    Ok(EncodedModrmMemory {
        rex_x,
        rex_b,
        mod_bits,
        rm_low_bits,
        sib,
        displacement,
    })
}

fn render_memory(memory: &crate::model::MemoryOperand) -> String {
    let mut text = String::from("[");
    if let Some(base) = &memory.base {
        text.push_str(&base.name);
    }
    if let Some(index) = &memory.index {
        if memory.base.is_some() {
            text.push('+');
        }
        text.push_str(&index.name);
        if memory.scale > 1 {
            text.push('*');
            text.push_str(&memory.scale.to_string());
        }
    }
    if memory.offset != 0 {
        if memory.offset > 0 {
            text.push('+');
            text.push_str(&format!("0x{:x}", memory.offset));
        } else {
            if memory.base.is_some() || memory.index.is_some() {
                text.push('+');
            } else {
                text.push('-');
            }
            text.push_str(&format!("-0x{:x}", memory.offset.unsigned_abs()));
        }
    }
    text.push(']');
    text
}

#[derive(Clone, Copy)]
struct RexPrefix {
    b: u8,
    x: u8,
}

pub fn rex_extension_bits(bytes: &[u8], limit: usize) -> (u8, u8, u8) {
    match bytes.first().copied() {
        Some(rex) if limit > 0 && (0x40..=0x4f).contains(&rex) => {
            (rex & 0x01, (rex >> 1) & 0x01, (rex >> 2) & 0x01)
        }
        Some(0xc4) if limit > 2 => {
            let vex = bytes.get(1).copied().unwrap_or(0xff);
            (
                ((!vex) & 0x20) >> 5,
                ((!vex) & 0x40) >> 6,
                ((!vex) & 0x80) >> 7,
            )
        }
        Some(0xc5) if limit > 1 => {
            let vex = bytes.get(1).copied().unwrap_or(0xff);
            (0, 0, ((!vex) & 0x80) >> 7)
        }
        _ => (0, 0, 0),
    }
}

fn extension_prefix(bytes: &[u8], limit: usize) -> RexPrefix {
    let (b, x, _) = rex_extension_bits(bytes, limit);
    RexPrefix { b, x }
}

fn extend_reg(value: u8, extension: u8) -> u8 {
    value | (extension << 3)
}

fn read_i8(bytes: &[u8], offset: usize) -> Result<i8, DecodeError> {
    Ok(*bytes.get(offset).ok_or(DecodeError::TruncatedInstruction {
        expected: offset + 1,
        actual: bytes.len(),
    })? as i8)
}

fn read_i32_as_i64(bytes: &[u8], offset: usize) -> Result<i64, DecodeError> {
    Ok(i64::from(i32::from_le_bytes([
        *bytes.get(offset).ok_or(DecodeError::TruncatedInstruction {
            expected: offset + 4,
            actual: bytes.len(),
        })?,
        *bytes
            .get(offset + 1)
            .ok_or(DecodeError::TruncatedInstruction {
                expected: offset + 4,
                actual: bytes.len(),
            })?,
        *bytes
            .get(offset + 2)
            .ok_or(DecodeError::TruncatedInstruction {
                expected: offset + 4,
                actual: bytes.len(),
            })?,
        *bytes
            .get(offset + 3)
            .ok_or(DecodeError::TruncatedInstruction {
                expected: offset + 4,
                actual: bytes.len(),
            })?,
    ])))
}

fn require_len(bytes: &[u8], offset: usize, width: usize) -> Result<usize, DecodeError> {
    if bytes.len() < offset + width {
        Err(DecodeError::TruncatedInstruction {
            expected: offset + width,
            actual: bytes.len(),
        })
    } else {
        Ok(width)
    }
}

fn displacement_mod_bits(offset: i64, force_displacement: bool) -> Result<u8, EncodeError> {
    if offset == 0 && !force_displacement {
        Ok(0b00)
    } else if i8::try_from(offset).is_ok() {
        Ok(0b01)
    } else if i32::try_from(offset).is_ok() {
        Ok(0b10)
    } else {
        Err(EncodeError::OperandMismatch(
            "x86 memory operand".to_string(),
        ))
    }
}

fn encode_displacement(offset: i64, force_displacement: bool) -> Result<Vec<u8>, EncodeError> {
    if offset == 0 && !force_displacement {
        Ok(Vec::new())
    } else if let Ok(disp8) = i8::try_from(offset) {
        Ok(vec![disp8 as u8])
    } else {
        let disp32 = i32::try_from(offset)
            .map_err(|_| EncodeError::OperandMismatch("x86 memory operand".to_string()))?;
        Ok(disp32.to_le_bytes().to_vec())
    }
}
