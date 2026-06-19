use crate::{
    arch::{aarch64::adapters, x86_64::adapters as x86_adapters},
    error::EncodeError,
    form::FormSchema,
    model::{Architecture, Instruction},
};

pub fn canonicalize_instruction(
    _forms: &'static [FormSchema],
    instruction: &Instruction,
) -> Result<Instruction, EncodeError> {
    Ok(instruction.clone())
}

pub fn display_text(forms: &'static [FormSchema], instruction: &Instruction) -> String {
    if let Some(form_name) = &instruction.form {
        if let Some(form) = forms.iter().find(|form| form.id().name() == *form_name) {
            return crate::runtime::text::render_instruction(form, instruction);
        }
    }

    if !instruction.text.is_empty() {
        instruction.text.clone()
    } else if instruction.operands.is_empty() {
        instruction.mnemonic.clone()
    } else {
        let rendered = match instruction.architecture {
            Architecture::Aarch64 => adapters::format_operands(&instruction.operands),
            Architecture::X86_64 => x86_adapters::format_operands(&instruction.operands),
        };
        format!("{} {}", instruction.mnemonic, rendered)
    }
}
