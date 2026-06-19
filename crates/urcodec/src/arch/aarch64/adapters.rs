use crate::{
    arch::aarch64::registers::{w, w_or_sp, w_or_zr, x, x_or_sp, x_or_zr},
    model::{MemoryOperand, Operand, Register},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairRegisterKind {
    W,
    X,
    Q,
}

pub fn condition_name(cond: u32) -> Option<&'static str> {
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

pub fn conditional_select_condition_name(cond: u32) -> Option<&'static str> {
    Some(match cond {
        0x2 => "hs",
        0x3 => "lo",
        _ => condition_name(cond)?,
    })
}

pub fn invert_condition(cond: u32) -> u32 {
    if cond < 0xe {
        cond ^ 1
    } else {
        cond
    }
}

pub fn condition_bits(name: &str) -> Option<u32> {
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

pub fn conditional_select_condition_bits(name: &str) -> Option<u32> {
    Some(match name {
        "hs" => 0x2,
        "lo" => 0x3,
        _ => condition_bits(name)?,
    })
}

pub fn x_only_register(index: u32) -> Register {
    x(index)
}

pub fn width_register(index: u32, is_64: bool) -> Register {
    if is_64 {
        x(index)
    } else {
        w(index)
    }
}

pub fn sp_capable_register(index: u32, is_64: bool) -> Register {
    if is_64 {
        x_or_sp(index)
    } else {
        w_or_sp(index)
    }
}

pub fn zr_capable_register(index: u32, is_64: bool) -> Register {
    if is_64 {
        x_or_zr(index)
    } else {
        w_or_zr(index)
    }
}

pub fn parse_width_register(name: &str) -> Option<(bool, u32)> {
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

pub fn parse_sp_capable_register(name: &str) -> Option<(bool, u32)> {
    match name {
        "sp" => Some((true, 31)),
        "wsp" => Some((false, 31)),
        _ => parse_width_register(name),
    }
}

pub fn parse_x_sp_register(name: &str) -> Option<u32> {
    match name {
        "sp" => Some(31),
        _ => name.strip_prefix('x')?.parse().ok(),
    }
}

pub fn parse_x_only_register(name: &str) -> Option<u32> {
    match name {
        "lr" => Some(30),
        _ => name.strip_prefix('x')?.parse().ok(),
    }
}

pub fn parse_pair_register(name: &str) -> Option<(PairRegisterKind, u32)> {
    if name == "xzr" {
        return Some((PairRegisterKind::X, 31));
    }
    if name == "wzr" {
        return Some((PairRegisterKind::W, 31));
    }
    if let Some(index) = name.strip_prefix('q') {
        return Some((PairRegisterKind::Q, index.parse().ok()?));
    }
    if let Some(index) = name.strip_prefix('x') {
        return Some((PairRegisterKind::X, index.parse().ok()?));
    }
    if let Some(index) = name.strip_prefix('w') {
        return Some((PairRegisterKind::W, index.parse().ok()?));
    }
    None
}

pub fn pair_register(index: u32, kind: PairRegisterKind) -> Register {
    match kind {
        PairRegisterKind::W => w_or_zr(index),
        PairRegisterKind::X => x_or_zr(index),
        PairRegisterKind::Q => crate::arch::aarch64::registers::q(index),
    }
}

pub fn parse_v2d_register(name: &str) -> Option<u32> {
    let (prefix, lane) = name.split_once('.')?;
    if lane != "2d" {
        return None;
    }
    prefix.strip_prefix('v')?.parse().ok()
}

pub fn parse_q_only_register(name: &str) -> Option<u32> {
    name.strip_prefix('q')?.parse().ok()
}

pub fn parse_aarch64_immediate(text: &str) -> Option<i64> {
    let text = text.trim();
    if let Some(hex) = text.strip_prefix("#-0x") {
        return Some(-i64::from_str_radix(hex, 16).ok()?);
    }
    if let Some(hex) = text.strip_prefix("#0x") {
        return i64::from_str_radix(hex, 16).ok();
    }
    None
}

pub fn parse_target_text(text: &str) -> Option<u64> {
    u64::from_str_radix(text.trim().strip_prefix("0x")?, 16).ok()
}

pub fn format_immediate(value: i64) -> String {
    if value < 0 {
        format!("#-0x{:x}", value.unsigned_abs())
    } else {
        format!("#0x{:x}", value as u64)
    }
}

pub fn format_address(value: u64) -> String {
    format!("0x{value:x}")
}

pub fn shift_name(bits: u32) -> Option<&'static str> {
    Some(match bits {
        0 => "lsl",
        1 => "lsr",
        2 => "asr",
        _ => return None,
    })
}

pub fn shift_bits(name: &str) -> Option<u32> {
    Some(match name {
        "lsl" => 0,
        "lsr" => 1,
        "asr" => 2,
        _ => return None,
    })
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
        Operand::ShiftedRegister(shifted) => {
            format!(
                "{}, {} {}",
                shifted.register.name,
                shifted.shift,
                format_immediate(i64::from(shifted.amount))
            )
        }
        Operand::Memory(memory) => render_memory(memory),
    }
}

fn render_memory(memory: &MemoryOperand) -> String {
    if is_aarch64_memory(memory) {
        render_aarch64_memory(memory)
    } else {
        render_generic_memory(memory)
    }
}

fn render_aarch64_memory(memory: &MemoryOperand) -> String {
    let base = memory
        .base
        .as_ref()
        .map(|register| register.name.as_str())
        .unwrap_or("unknown");

    if let Some(index) = &memory.index {
        let extend = if index.name.starts_with('w') {
            "uxtw"
        } else {
            "lsl"
        };
        let shift = memory.scale.trailing_zeros();
        if shift == 0 {
            return format!("[{base}, {}, {extend}]", index.name);
        }
        return format!("[{base}, {}, {extend} #0x{shift:x}]", index.name);
    }

    if memory.offset == 0 && !memory.writeback && !memory.post_index {
        format!("[{base}]")
    } else if memory.post_index {
        format!("[{base}], {}", format_immediate(memory.offset))
    } else if memory.writeback {
        format!("[{base}, {}]!", format_immediate(memory.offset))
    } else {
        format!("[{base}, {}]", format_immediate(memory.offset))
    }
}

fn render_generic_memory(memory: &MemoryOperand) -> String {
    let mut text = String::from("[");
    if let Some(base) = &memory.base {
        text.push_str(&base.name);
    }
    if memory.offset != 0 {
        if memory.offset > 0 {
            text.push('+');
            text.push_str(&format!("0x{:x}", memory.offset));
        } else {
            text.push('-');
            text.push_str(&format!("0x{:x}", memory.offset.unsigned_abs()));
        }
    }
    text.push(']');
    text
}

fn is_aarch64_memory(memory: &MemoryOperand) -> bool {
    [memory.base.as_ref(), memory.index.as_ref()]
        .into_iter()
        .flatten()
        .any(|register| {
            matches!(register.name.as_str(), "sp" | "wsp" | "xzr" | "wzr" | "lr")
                || matches!(register.name.chars().next(), Some('x' | 'w' | 'q' | 'v'))
        })
}

pub fn encode_add_sub_immediate(value: i64) -> Option<(u32, bool)> {
    if value < 0 {
        return None;
    }
    let value = u32::try_from(value).ok()?;
    if value <= 0x0fff {
        Some((value, false))
    } else if value & 0x0fff == 0 && (value >> 12) <= 0x0fff {
        Some((value >> 12, true))
    } else {
        None
    }
}

pub fn encode_move_wide_immediate(value: u64, is_64: bool) -> Option<(u32, u32)> {
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

pub fn encode_logical_immediate_fields(mask: u64, is_64: bool) -> Option<(u32, u32, u32)> {
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

pub fn decode_logical_immediate_mask(n: u32, immr: u32, imms: u32, reg_size: u32) -> Option<u64> {
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
