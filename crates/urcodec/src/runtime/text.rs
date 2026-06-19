use crate::{
    arch::{aarch64::adapters, x86_64::adapters as x86_adapters},
    error::TextError,
    form::{FormSchema, MemorySpec},
    model::{Architecture, DecodeStatus, Instruction, MemoryOperand, Operand},
};

pub fn render_instruction(_form: &FormSchema, instruction: &Instruction) -> String {
    if instruction.operands.is_empty() {
        instruction.mnemonic.clone()
    } else {
        let rendered = match instruction.architecture {
            Architecture::Aarch64 => adapters::format_operands(&instruction.operands),
            Architecture::X86_64 => x86_adapters::format_operands(&instruction.operands),
        };
        format!("{} {}", instruction.mnemonic, rendered)
    }
}

pub fn parse_instruction(
    architecture: Architecture,
    forms: &'static [FormSchema],
    text: &str,
) -> Result<Instruction, TextError> {
    parse_candidates(architecture, forms, text)?
        .into_iter()
        .next()
        .ok_or_else(|| TextError::InvalidOperand(text.trim().to_string()))
}

pub fn parse_candidates(
    architecture: Architecture,
    forms: &'static [FormSchema],
    text: &str,
) -> Result<Vec<Instruction>, TextError> {
    let trimmed = text.trim();
    let (mnemonic, operand_texts) = split_text(trimmed)?;
    let mut candidates = Vec::new();
    let mut saw_mnemonic = false;
    for form in forms.iter().filter(|form| mnemonic_matches(form, mnemonic)) {
        saw_mnemonic = true;
        let Ok(operands) = parse_operands(form, mnemonic, &operand_texts) else {
            continue;
        };
        candidates.push(Instruction {
            architecture,
            address: 0,
            size: if matches!(architecture, Architecture::Aarch64) {
                4
            } else {
                1
            },
            bytes: Vec::new(),
            mnemonic: mnemonic.to_string(),
            operands,
            text: String::new(),
            kind: form.kind(),
            flow: form.flow(),
            branch_target: None,
            status: DecodeStatus::Complete,
            form: Some(form.id().name()),
        });
    }

    if !candidates.is_empty() {
        Ok(candidates)
    } else if saw_mnemonic {
        Err(TextError::InvalidOperand(trimmed.to_string()))
    } else {
        Err(TextError::UnknownMnemonic(trimmed.to_string()))
    }
}

fn mnemonic_matches(form: &FormSchema, mnemonic: &str) -> bool {
    form.text_rule().mnemonic == mnemonic
        || (form.id().name() == "aarch64.b_cond" && mnemonic.starts_with("b."))
}

fn split_text(text: &str) -> Result<(&str, Vec<&str>), TextError> {
    let text = text.trim();
    if let Some((mnemonic, rest)) = text.split_once(' ') {
        let operands = split_operands(rest)?;
        Ok((mnemonic.trim(), operands))
    } else {
        Ok((text, Vec::new()))
    }
}

fn parse_operands(
    form: &FormSchema,
    mnemonic: &str,
    operand_texts: &[&str],
) -> Result<Vec<Operand>, TextError> {
    if form.id().name() == "aarch64.ret" && operand_texts.is_empty() {
        return Ok(Vec::new());
    }

    let mut operands = Vec::with_capacity(form.operands().len());
    let mut text_index = 0;

    for operand in form.operands() {
        let text = operand_texts
            .get(text_index)
            .copied()
            .ok_or_else(|| TextError::InvalidOperand(mnemonic.to_string()))?;
        let parsed = match operand {
            crate::form::OperandSpec::FixedRegister { name } => {
                text_index += 1;
                if text != *name {
                    return Err(TextError::InvalidOperand(text.to_string()));
                }
                Operand::Register(crate::model::Register {
                    name: (*name).to_string(),
                })
            }
            crate::form::OperandSpec::FixedMemory { base, width_bits } => {
                text_index += 1;
                let expected = Operand::Memory(MemoryOperand::base_offset(
                    crate::model::Register {
                        name: (*base).to_string(),
                    },
                    0,
                    Some(*width_bits),
                ));
                if x86_adapters::format_operand(&expected) != text {
                    return Err(TextError::InvalidOperand(text.to_string()));
                }
                expected
            }
            crate::form::OperandSpec::Register { bank, .. } => {
                text_index += 1;
                parse_register_operand(bank, text)?
            }
            crate::form::OperandSpec::ShiftedRegister { bank, .. } => {
                let shift_text = operand_texts
                    .get(text_index + 1)
                    .copied()
                    .ok_or_else(|| TextError::InvalidOperand(mnemonic.to_string()))?;
                text_index += 2;
                let register = match parse_register_operand(bank, text)? {
                    Operand::Register(register) => register,
                    _ => return Err(TextError::InvalidOperand(text.to_string())),
                };
                let (shift, amount) = parse_shifted_suffix(shift_text)?;
                Operand::ShiftedRegister(crate::model::ShiftedRegisterOperand {
                    register,
                    shift,
                    amount,
                })
            }
            crate::form::OperandSpec::Immediate { .. } => {
                text_index += 1;
                Operand::Immediate(parse_immediate_operand(architecture_for_form(form), text)?)
            }
            crate::form::OperandSpec::RelativeTarget { .. }
            | crate::form::OperandSpec::AbsoluteTarget { .. } => {
                text_index += 1;
                Operand::AbsoluteAddress(parse_target_operand(architecture_for_form(form), text)?)
            }
            crate::form::OperandSpec::Condition { .. } => {
                text_index += 1;
                Operand::Condition(parse_condition_operand(operand, text)?)
            }
            crate::form::OperandSpec::Memory { kind } => {
                let combined = if matches!(
                    kind,
                    MemorySpec::Aarch64SignedOffset {
                        post_index: true,
                        ..
                    }
                ) {
                    let suffix = operand_texts
                        .get(text_index + 1)
                        .copied()
                        .ok_or_else(|| TextError::InvalidOperand(mnemonic.to_string()))?;
                    text_index += 2;
                    format!("{text}, {suffix}")
                } else {
                    text_index += 1;
                    text.to_string()
                };
                Operand::Memory(parse_memory_operand(kind, &combined)?)
            }
        };
        operands.push(parsed);
    }

    if text_index != operand_texts.len() {
        return Err(TextError::InvalidOperand(mnemonic.to_string()));
    }

    Ok(operands)
}

fn split_operands(text: &str) -> Result<Vec<&str>, TextError> {
    let mut operands = Vec::new();
    let mut start = 0usize;
    let mut depth = 0u32;

    for (index, ch) in text.char_indices() {
        match ch {
            '[' => depth += 1,
            ']' => {
                if depth == 0 {
                    return Err(TextError::InvalidOperand(text.trim().to_string()));
                }
                depth -= 1;
            }
            ',' if depth == 0 => {
                let part = text[start..index].trim();
                if !part.is_empty() {
                    operands.push(part);
                }
                start = index + ch.len_utf8();
            }
            _ => {}
        }
    }

    if depth != 0 {
        return Err(TextError::InvalidOperand(text.trim().to_string()));
    }

    let tail = text[start..].trim();
    if !tail.is_empty() {
        operands.push(tail);
    }
    Ok(operands)
}

fn parse_register_operand(bank: &str, text: &str) -> Result<Operand, TextError> {
    match bank {
        "aarch64.x_only" | "aarch64.ret" => {
            let index = adapters::parse_x_only_register(text)
                .ok_or_else(|| TextError::InvalidOperand(text.to_string()))?;
            Ok(Operand::Register(adapters::x_only_register(index)))
        }
        "aarch64.width_gp" | "aarch64.tb_width_gp" => {
            let (is_64, index) = adapters::parse_width_register(text)
                .ok_or_else(|| TextError::InvalidOperand(text.to_string()))?;
            Ok(Operand::Register(adapters::width_register(index, is_64)))
        }
        "aarch64.access_gp" => {
            let (is_64, index) = adapters::parse_width_register(text)
                .ok_or_else(|| TextError::InvalidOperand(text.to_string()))?;
            Ok(Operand::Register(adapters::width_register(index, is_64)))
        }
        "aarch64.width_gp_zr" => {
            let (is_64, index) = adapters::parse_width_register(text)
                .ok_or_else(|| TextError::InvalidOperand(text.to_string()))?;
            Ok(Operand::Register(adapters::zr_capable_register(
                index, is_64,
            )))
        }
        "aarch64.sp_width_gp" => {
            let (is_64, index) = adapters::parse_sp_capable_register(text)
                .ok_or_else(|| TextError::InvalidOperand(text.to_string()))?;
            Ok(Operand::Register(adapters::sp_capable_register(
                index, is_64,
            )))
        }
        "aarch64.v2d" => {
            let index = adapters::parse_v2d_register(text)
                .ok_or_else(|| TextError::InvalidOperand(text.to_string()))?;
            Ok(Operand::Register(crate::arch::aarch64::registers::v_lane(
                index, "2d",
            )))
        }
        "aarch64.q_only" => {
            let index = adapters::parse_q_only_register(text)
                .ok_or_else(|| TextError::InvalidOperand(text.to_string()))?;
            Ok(Operand::Register(crate::arch::aarch64::registers::q(index)))
        }
        "aarch64.pair_reg" => {
            let (kind, index) = adapters::parse_pair_register(text)
                .ok_or_else(|| TextError::InvalidOperand(text.to_string()))?;
            Ok(Operand::Register(adapters::pair_register(index, kind)))
        }
        "x86_64.r64" => {
            let index = x86_adapters::parse_r64_register(text)
                .ok_or_else(|| TextError::InvalidOperand(text.to_string()))?;
            Ok(Operand::Register(x86_adapters::r64_register(u32::from(
                index,
            ))))
        }
        "x86_64.r32" => {
            let index = x86_adapters::parse_r32_register(text)
                .ok_or_else(|| TextError::InvalidOperand(text.to_string()))?;
            Ok(Operand::Register(x86_adapters::r32_register(u32::from(
                index,
            ))))
        }
        "x86_64.r16" => {
            let index = x86_adapters::parse_r16_register(text)
                .ok_or_else(|| TextError::InvalidOperand(text.to_string()))?;
            Ok(Operand::Register(x86_adapters::r16_register(u32::from(
                index,
            ))))
        }
        "x86_64.r8" => {
            let index = x86_adapters::parse_r8_register(text)
                .ok_or_else(|| TextError::InvalidOperand(text.to_string()))?;
            Ok(Operand::Register(x86_adapters::r8_register(u32::from(
                index,
            ))))
        }
        "x86_64.mm" => {
            let index = x86_adapters::parse_mm_register(text)
                .ok_or_else(|| TextError::InvalidOperand(text.to_string()))?;
            Ok(Operand::Register(x86_adapters::mm_register(u32::from(
                index,
            ))))
        }
        "x86_64.xmm" => {
            let index = x86_adapters::parse_xmm_register(text)
                .ok_or_else(|| TextError::InvalidOperand(text.to_string()))?;
            Ok(Operand::Register(x86_adapters::xmm_register(u32::from(
                index,
            ))))
        }
        "x86_64.ymm" => {
            let index = x86_adapters::parse_ymm_register(text)
                .ok_or_else(|| TextError::InvalidOperand(text.to_string()))?;
            Ok(Operand::Register(x86_adapters::ymm_register(u32::from(
                index,
            ))))
        }
        _ => Err(TextError::InvalidOperand(text.to_string())),
    }
}

fn parse_immediate_operand(architecture: Architecture, text: &str) -> Result<i64, TextError> {
    match architecture {
        Architecture::Aarch64 => adapters::parse_aarch64_immediate(text),
        Architecture::X86_64 => x86_adapters::parse_immediate(text),
    }
    .ok_or_else(|| TextError::InvalidOperand(text.to_string()))
}

fn parse_target_operand(architecture: Architecture, text: &str) -> Result<u64, TextError> {
    match architecture {
        Architecture::Aarch64 => adapters::parse_target_text(text),
        Architecture::X86_64 => x86_adapters::parse_target_text(text),
    }
    .ok_or_else(|| TextError::InvalidOperand(text.to_string()))
}

fn architecture_for_form(form: &FormSchema) -> Architecture {
    form.id().architecture()
}

fn parse_shifted_suffix(text: &str) -> Result<(String, u8), TextError> {
    let (shift, amount_text) = text
        .trim()
        .split_once(' ')
        .ok_or_else(|| TextError::InvalidOperand(text.to_string()))?;
    adapters::shift_bits(shift).ok_or_else(|| TextError::InvalidOperand(text.to_string()))?;
    let amount = adapters::parse_aarch64_immediate(amount_text)
        .ok_or_else(|| TextError::InvalidOperand(text.to_string()))?;
    let amount = u8::try_from(amount).map_err(|_| TextError::InvalidOperand(text.to_string()))?;
    Ok((shift.to_string(), amount))
}

fn parse_condition_operand(
    operand: &crate::form::OperandSpec,
    text: &str,
) -> Result<String, TextError> {
    let crate::form::OperandSpec::Condition { table, .. } = operand else {
        return Err(TextError::InvalidOperand(text.to_string()));
    };
    match *table {
        "aarch64.condsel" => adapters::conditional_select_condition_bits(text)
            .and_then(adapters::conditional_select_condition_name)
            .map(str::to_string),
        "aarch64.condsel_inverted" => adapters::conditional_select_condition_bits(text)
            .and_then(adapters::conditional_select_condition_name)
            .map(str::to_string),
        _ => adapters::condition_bits(text)
            .and_then(adapters::condition_name)
            .map(str::to_string),
    }
    .ok_or_else(|| TextError::InvalidOperand(text.to_string()))
}

fn parse_memory_operand(kind: &MemorySpec, text: &str) -> Result<MemoryOperand, TextError> {
    match kind {
        MemorySpec::X86Modrm { width_bits } => parse_x86_memory_operand(*width_bits, text),
        MemorySpec::Aarch64UnsignedOffset { .. } => {
            let memory = parse_aarch64_memory_operand(text)?;
            if memory.index.is_some() || memory.writeback || memory.post_index {
                return Err(TextError::InvalidOperand(text.to_string()));
            }
            Ok(memory)
        }
        MemorySpec::Aarch64SignedOffset {
            writeback,
            post_index,
            ..
        } => {
            let memory = parse_aarch64_memory_operand(text)?;
            if memory.index.is_some()
                || memory.writeback != *writeback
                || memory.post_index != *post_index
            {
                return Err(TextError::InvalidOperand(text.to_string()));
            }
            Ok(memory)
        }
        MemorySpec::Aarch64RegisterOffset { .. } => {
            let memory = parse_aarch64_memory_operand(text)?;
            if memory.index.is_none() || memory.writeback || memory.post_index || memory.offset != 0
            {
                return Err(TextError::InvalidOperand(text.to_string()));
            }
            Ok(memory)
        }
        MemorySpec::Aarch64PairOffset {
            writeback,
            post_index,
            ..
        } => {
            let memory = parse_aarch64_memory_operand(text)?;
            if memory.index.is_some()
                || memory.writeback != *writeback
                || memory.post_index != *post_index
            {
                return Err(TextError::InvalidOperand(text.to_string()));
            }
            Ok(memory)
        }
    }
}

fn parse_aarch64_memory_operand(text: &str) -> Result<MemoryOperand, TextError> {
    let trimmed = text.trim();
    let mut writeback = false;
    let mut post_index = false;
    let mut post_offset = None;

    let inner = if let Some((head, tail)) = trimmed.split_once("],") {
        post_index = true;
        post_offset = Some(
            adapters::parse_aarch64_immediate(tail.trim())
                .ok_or_else(|| TextError::InvalidOperand(text.to_string()))?,
        );
        head.trim()
            .strip_prefix('[')
            .ok_or_else(|| TextError::InvalidOperand(text.to_string()))?
    } else if let Some(inner) = trimmed.strip_suffix("]!") {
        writeback = true;
        inner
            .trim()
            .strip_prefix('[')
            .ok_or_else(|| TextError::InvalidOperand(text.to_string()))?
    } else {
        trimmed
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .ok_or_else(|| TextError::InvalidOperand(text.to_string()))?
    };

    let parts = split_operands(inner)?;
    let base_name = parts
        .first()
        .copied()
        .ok_or_else(|| TextError::InvalidOperand(text.to_string()))?;
    let base = Some(crate::arch::aarch64::registers::x_or_sp(
        adapters::parse_x_sp_register(base_name)
            .ok_or_else(|| TextError::InvalidOperand(text.to_string()))?,
    ));

    let mut memory = MemoryOperand {
        base,
        index: None,
        scale: 1,
        offset: 0,
        width_bits: None,
        writeback,
        post_index,
        relative: false,
    };

    match parts.as_slice() {
        [_] => {}
        [_, offset_text] if offset_text.trim_start().starts_with('#') => {
            memory.offset = adapters::parse_aarch64_immediate(offset_text.trim())
                .ok_or_else(|| TextError::InvalidOperand(text.to_string()))?;
        }
        [_, index_text] => {
            memory.index = Some(parse_memory_index(index_text.trim())?);
        }
        [_, index_text, extend_text] => {
            memory.index = Some(parse_memory_index(index_text.trim())?);
            memory.scale = parse_memory_scale(extend_text.trim())?;
        }
        _ => return Err(TextError::InvalidOperand(text.to_string())),
    }

    if let Some(offset) = post_offset {
        memory.offset = offset;
    }

    Ok(memory)
}

fn parse_x86_memory_operand(width_bits: u16, text: &str) -> Result<MemoryOperand, TextError> {
    let inner = text
        .trim()
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .ok_or_else(|| TextError::InvalidOperand(text.to_string()))?;
    let mut base = None;
    let mut index = None;
    let mut scale = 1u8;
    let mut offset = 0i64;

    for term in split_x86_memory_terms(inner)? {
        let trimmed = term.trim();
        if trimmed.is_empty() {
            return Err(TextError::InvalidOperand(text.to_string()));
        }
        if let Some((index_text, scale_text)) = trimmed.split_once('*') {
            if index.is_some() {
                return Err(TextError::InvalidOperand(text.to_string()));
            }
            index = Some(parse_x86_memory_register(index_text.trim(), false)?);
            scale = scale_text
                .trim()
                .parse::<u8>()
                .ok()
                .filter(|value| matches!(value, 1 | 2 | 4 | 8))
                .ok_or_else(|| TextError::InvalidOperand(text.to_string()))?;
        } else if let Ok(register) = parse_x86_memory_register(trimmed, base.is_none()) {
            if base.is_none() {
                base = Some(register);
            } else if index.is_none() {
                index = Some(register);
            } else {
                return Err(TextError::InvalidOperand(text.to_string()));
            }
        } else {
            let value = x86_adapters::parse_immediate(trimmed)
                .ok_or_else(|| TextError::InvalidOperand(text.to_string()))?;
            offset += value;
        }
    }

    let Some(base_register) = base.as_ref() else {
        return Err(TextError::InvalidOperand(text.to_string()));
    };
    if base_register.name == "rip" {
        if index.is_some() {
            return Err(TextError::InvalidOperand(text.to_string()));
        }
        return Ok(MemoryOperand::rip_relative(offset, Some(width_bits)));
    }

    Ok(MemoryOperand::indexed(
        base,
        index,
        scale,
        offset,
        Some(width_bits),
    ))
}

fn split_x86_memory_terms(text: &str) -> Result<Vec<&str>, TextError> {
    let mut terms = Vec::new();
    let mut start = 0usize;

    for (index, ch) in text.char_indices() {
        if (ch == '+' || ch == '-') && index != 0 {
            let term = text[start..index].trim();
            if !term.is_empty() {
                terms.push(term);
            }
            start = if ch == '+' { index + 1 } else { index };
        }
    }

    let tail = text[start..].trim();
    if !tail.is_empty() {
        terms.push(tail);
    }

    if terms.is_empty() {
        return Err(TextError::InvalidOperand(text.trim().to_string()));
    }

    Ok(terms)
}

fn parse_x86_memory_register(
    text: &str,
    allow_rip: bool,
) -> Result<crate::model::Register, TextError> {
    if allow_rip && text == "rip" {
        return Ok(crate::model::Register {
            name: "rip".to_string(),
        });
    }
    let index = x86_adapters::parse_r64_register(text)
        .ok_or_else(|| TextError::InvalidOperand(text.to_string()))?;
    Ok(x86_adapters::r64_register(u32::from(index)))
}

fn parse_memory_index(text: &str) -> Result<crate::model::Register, TextError> {
    let (is_64, index) = adapters::parse_width_register(text)
        .ok_or_else(|| TextError::InvalidOperand(text.to_string()))?;
    Ok(if is_64 {
        crate::arch::aarch64::registers::x(index)
    } else {
        crate::arch::aarch64::registers::w(index)
    })
}

fn parse_memory_scale(text: &str) -> Result<u8, TextError> {
    let (extend, shift_text) = text
        .split_once(' ')
        .ok_or_else(|| TextError::InvalidOperand(text.to_string()))?;
    match extend {
        "uxtw" | "lsl" => {}
        _ => return Err(TextError::InvalidOperand(text.to_string())),
    }
    let shift = adapters::parse_aarch64_immediate(shift_text.trim())
        .ok_or_else(|| TextError::InvalidOperand(text.to_string()))?;
    let shift = u32::try_from(shift).map_err(|_| TextError::InvalidOperand(text.to_string()))?;
    let scale = 1u32
        .checked_shl(shift)
        .ok_or_else(|| TextError::InvalidOperand(text.to_string()))?;
    u8::try_from(scale).map_err(|_| TextError::InvalidOperand(text.to_string()))
}
