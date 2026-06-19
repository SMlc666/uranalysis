pub mod alias;
pub mod encode;
pub mod fields;
pub mod layout;
pub mod matcher;
pub mod operands;
pub mod text;

use crate::{
    error::{DecodeError, EncodeError, TextError},
    form::FormSchema,
    model::{Architecture, DecodeStatus, FlowKind, Instruction, InstructionKind, Operand},
};
use std::collections::BTreeMap;

pub fn decode_one(
    architecture: Architecture,
    forms: &'static [FormSchema],
    bytes: &[u8],
    address: u64,
) -> Result<Instruction, DecodeError> {
    let layout = layout::read_layout(architecture, bytes, address)?;
    for form in matcher::matching_forms(forms, &layout) {
        let values = match fields::extract_fields(form, &layout) {
            Ok(values) => values,
            Err(DecodeError::UnsupportedTarget) => continue,
            Err(err) => return Err(err),
        };
        let mut instruction = match operands::build_instruction(form, &layout, &values) {
            Ok(instruction) => instruction,
            Err(DecodeError::UnsupportedTarget) => continue,
            Err(err) => return Err(err),
        };
        instruction.text = text::render_instruction(form, &instruction);
        return Ok(instruction);
    }

    match architecture {
        Architecture::X86_64 => Ok(Instruction {
            architecture,
            address,
            size: 1,
            bytes: vec![bytes[0]],
            mnemonic: ".byte".to_string(),
            operands: vec![crate::model::Operand::Immediate(i64::from(bytes[0]))],
            text: format!(".byte 0x{:02x}", bytes[0]),
            kind: InstructionKind::Unknown,
            flow: FlowKind::Fallthrough,
            branch_target: None,
            status: DecodeStatus::Unknown,
            form: None,
        }),
        Architecture::Aarch64 => {
            let word = bytes.get(..4).ok_or(DecodeError::TruncatedInstruction {
                expected: 4,
                actual: bytes.len(),
            })?;
            let value = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
            Ok(Instruction {
                architecture,
                address,
                size: 4,
                bytes: word.to_vec(),
                mnemonic: ".word".to_string(),
                operands: vec![crate::model::Operand::Immediate(i64::from(value))],
                text: format!(".word 0x{value:08x}"),
                kind: InstructionKind::Unknown,
                flow: FlowKind::Fallthrough,
                branch_target: None,
                status: DecodeStatus::Unknown,
                form: None,
            })
        }
    }
}

pub fn encode_one(
    forms: &'static [FormSchema],
    instruction: &Instruction,
) -> Result<Vec<u8>, EncodeError> {
    let canonical = alias::canonicalize_instruction(forms, instruction)?;
    let form = matcher::select_form_for_instruction(forms, &canonical)?;
    let values = operands::match_instruction(form, &canonical)?;
    encode::emit_instruction(form, &canonical, &values)
}

pub fn parse_one(
    architecture: Architecture,
    forms: &'static [FormSchema],
    text: &str,
    address: u64,
) -> Result<Instruction, TextError> {
    for mut instruction in text::parse_candidates(architecture, forms, text)? {
        instruction.address = address;
        let form = matcher::select_form_for_instruction(forms, &instruction)
            .map_err(|_| TextError::UnknownMnemonic(text.trim().to_string()))?;
        let Ok(values) = operands::match_instruction(form, &instruction) else {
            continue;
        };
        if matches!(architecture, Architecture::X86_64)
            && instruction
                .operands
                .iter()
                .any(|operand| matches!(operand, Operand::Memory(_)))
        {
            instruction.text = text::render_instruction(form, &instruction);
            instruction.branch_target = instruction.operands.iter().find_map(|operand| {
                if let Operand::AbsoluteAddress(target) = operand {
                    Some(*target)
                } else {
                    None
                }
            });
            return Ok(instruction);
        }
        let mut rebuilt =
            operands::build_instruction_from_values(architecture, form, address, &values)?;
        rebuilt.text = text::render_instruction(form, &rebuilt);
        return Ok(rebuilt);
    }

    Err(TextError::InvalidOperand(text.trim().to_string()))
}

pub fn format_instruction(forms: &'static [FormSchema], instruction: &Instruction) -> String {
    alias::display_text(forms, instruction)
}

pub type ValueMap = BTreeMap<&'static str, i64>;
