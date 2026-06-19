use crate::{
    error::{DecodeError, EncodeError},
    form::{DecodeLayout, FormSchema, Matcher},
    model::Instruction,
    runtime::layout::LayoutView,
};

pub fn select_form(
    forms: &'static [FormSchema],
    layout: &LayoutView,
) -> Result<&'static FormSchema, DecodeError> {
    matching_forms(forms, layout)
        .next()
        .ok_or(DecodeError::UnsupportedTarget)
}

pub fn matching_forms<'a>(
    forms: &'static [FormSchema],
    layout: &'a LayoutView,
) -> impl Iterator<Item = &'static FormSchema> + 'a {
    forms.iter().filter(|form| layout_matches(form, layout))
}

pub fn select_form_for_instruction(
    forms: &'static [FormSchema],
    instruction: &Instruction,
) -> Result<&'static FormSchema, EncodeError> {
    forms
        .iter()
        .find(|form| form.id().name() == instruction.form.clone().unwrap_or_default())
        .ok_or_else(|| EncodeError::UnsupportedForm(instruction.mnemonic.clone()))
}

fn layout_matches(form: &FormSchema, layout: &LayoutView) -> bool {
    match (form.decode_layout(), layout) {
        (DecodeLayout::FixedWidthBits { width: 32 }, LayoutView::Aarch64Word { word, .. }) => {
            form.matchers().iter().all(|matcher| match matcher {
                Matcher::MaskEq { mask, value } => word & mask == *value,
                _ => false,
            })
        }
        (DecodeLayout::ByteStream(_), LayoutView::X86ByteStream { bytes, .. }) => {
            form.matchers().iter().all(|matcher| match matcher {
                Matcher::OpcodeEq(opcode) => bytes.starts_with(opcode),
                Matcher::ByteMaskedEq {
                    offset,
                    mask,
                    value,
                } => bytes
                    .get(*offset as usize)
                    .is_some_and(|byte| byte & mask == *value),
                Matcher::OpcodeExt { reg } => {
                    modrm_byte(form, bytes).is_some_and(|modrm| ((modrm >> 3) & 0x07) == *reg)
                }
                Matcher::ModrmMode { mode } => {
                    modrm_byte(form, bytes).is_some_and(|modrm| (modrm >> 6) == *mode)
                }
                _ => false,
            })
        }
        _ => false,
    }
}

fn modrm_byte(form: &FormSchema, bytes: &[u8]) -> Option<u8> {
    let DecodeLayout::ByteStream(layout) = form.decode_layout() else {
        return None;
    };
    layout
        .uses_modrm
        .then(|| bytes.get(layout.opcode_len as usize).copied())
        .flatten()
}
